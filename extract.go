package xioc

import (
	"fmt"
	"regexp"
	"strings"
)

type Iocs struct {
	Domains []string
	Ips     []string
	Urls    []string
	Hashs   []string
	Emails  []string
}

func (ioc Iocs) IsEmpty() bool {
	if len(ioc.Domains) == 0 && len(ioc.Ips) == 0 && len(ioc.Urls) == 0 && len(ioc.Hashs) == 0 && len(ioc.Emails) == 0 {
		return true
	}
	return false
}

// 从文章中提取出ioc, 有分类
func ExtractIocs(content string) Iocs {
	var iocs Iocs
	iocs.Domains = ExtractDomains(content)
	iocs.Ips = ExtractIPs(content)
	iocs.Urls = ExtractUrls(content)
	iocs.Hashs = ExtractHashs(content)
	iocs.Emails = ExtractEmails(content)
	return iocs
}

// 从文章中提取出ioc, 无分类
func ExtractIocsList(content string) []string {
	var iocs []string
	iocs = append(iocs, ExtractDomains(content)...)
	iocs = append(iocs, ExtractIPs(content)...)
	iocs = append(iocs, ExtractUrls(content)...)
	iocs = append(iocs, ExtractHashs(content)...)
	iocs = append(iocs, ExtractEmails(content)...)
	return iocs
}

// 使用正则表达式从文章中提取原始域名(不做清洗)
func ExtractOriginDomains(content string) []string {
	//domainRegex := regexp.MustCompile(`(?i)(?P<domain>[a-zA-Z0-9-]+\.[a-zA-Z]+)`)
	// getpremiumapp[.]monster
	// 处理兼容 .、[.]、[. 或 . ]
	domainRegex := regexp.MustCompile(`(?i)(?P<domain>[a-zA-Z0-9]+((\[\.\]|\[\.|\.|\.\]|-)+[a-zA-Z0-9]+)+)`)
	domains := domainRegex.FindAllStringSubmatch(content, -1)
	var uniqueDomains, validDomains []string
	for _, domain := range domains {
		if len(domain) > 1 {
			domainStr := domain[1]
			if !contains(uniqueDomains, domainStr) {
				uniqueDomains = append(uniqueDomains, domainStr)
			}
		}
	}
	uniqueDomains = RemoveDuplicates(uniqueDomains)
	if len(uniqueDomains) > 0 {
		for _, v := range uniqueDomains {
			if isValidSuffix(v) {
				validDomains = append(validDomains, v)
			}
		}
		return validDomains
	}
	return uniqueDomains
}

// 使用正则表达式从文章中提取域名
func ExtractDomains(content string) []string {
	domains := ExtractOriginDomains(content)
	return ClearIoc(domains)
}

func ExtractOriginIPs(content string) []string {
	//ipRegex := regexp.MustCompile(`(?i)(?:\d{1,3}\.){3}\d{1,3}`)
	ipRegex := regexp.MustCompile(`(?i)(?:\d{1,3}(?:\[\.]|\.|\[\.|\.\])?){3}\d{1,3}`)
	ips := ipRegex.FindAllString(content, -1)
	ips = RemoveDuplicates(ips)
	return ips
}

// 使用正则表达式从文章中提取IP地址
func ExtractIPs(content string) []string {
	ips := ExtractOriginIPs(content)
	ips = ClearIoc(ips)
	ips = VerifyIocIp(ips)
	return ips
}

func ExtractOriginUrls(content string) []string {
	var rep = []string{
		"https",
		"http",
		"hxxps",
		"hxxp",
	}
	var urls []string
	for _, v := range rep {
		// 测试通过 https[:]//a13aaa1.oss-cn-hongkong.aliyuncs[.]com/hj/MEmuSVC.exe
		str := fmt.Sprintf(`(?i)%s?(\[:|\]:|\[:\]|:)//[a-zA-Z0-9-]+((\[\.\]|\[\.|\.|\.\]|\-|\/|\?|\_|\=|\_\=|:[0-9]+)+[a-zA-Z0-9-]+)+`, v)
		urlRegex := regexp.MustCompile(str)
		tmpUrls := urlRegex.FindAllString(content, -1)
		if len(tmpUrls) > 0 {
			urls = append(urls, tmpUrls...)
		}
	}
	// 27.102.107[.]224:8443
	str2 := `(?i)([a-zA-Z0-9-]+(\[\.\]|\[\.|\.|\.\]|\-|\_)?)+(\[:|\]:|\[:\]|:)[0-9]+`
	urlRegex2 := regexp.MustCompile(str2)
	urls = append(urls, urlRegex2.FindAllString(content, -1)...)
	// ultimate-boy-bacterial-generates[.]trycloudflare[.]com/sbi
	// ultimate-boy-bacterial-generates[.]trycloudflare[.]com:7777/a.zip
	// (\/[a-zA-Z0-9-_]+(\[\.\]|\[\.|\.|\.\]|\-|\_)?([a-zA-Z0-9-]+)?)+
	str3 := `(?i)([a-zA-Z0-9_-]+(\[\.\]|\[\.|\.|\.\]))+[a-zA-Z0-9]+((\[:|\]:|\[:\]|:)[0-9]+)?(\/[a-zA-Z0-9-_]+)+((\[\.\]|\[\.|\.|\.\]|\-|\_)([a-zA-Z0-9-]+))?`
	urlRegex3 := regexp.MustCompile(str3)
	urls = append(urls, urlRegex3.FindAllString(content, -1)...)
	tmpUrls := make([]string, 0)
	for i, v1 := range urls {
		if strings.Contains(v1, "://") {
			tmpUrls = append(tmpUrls, v1)
		} else {
			flag := true
			for j, v2 := range urls {
				if i != j {
					if strings.Contains(v2, v1) {
						flag = false
					}
				}
			}
			if flag {
				tmpUrls = append(tmpUrls, v1)
			}
		}
	}
	urls = RemoveDuplicates(tmpUrls)
	return urls
}

// 使用正则表达式从文章中提取URL
func ExtractUrls(content string) []string {
	urls := ExtractOriginUrls(content)
	return ClearIoc(urls)
}

// 使用正则表达式从文章中提取哈希值
func ExtractHashs(content string) []string {
	// 正则表达式，匹配MD5、SHA-1和SHA-256哈希值还有SHA-512；优先匹配SHA-256，然后是SHA-1，最后是MD5
	hashRegex := regexp.MustCompile(`([a-f0-9]{128}|[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})`)
	// 查找所有匹配的哈希值
	hashes := hashRegex.FindAllString(content, -1)
	// 去掉在url里面的hash
	urls := ExtractUrls(content)
	newhashs := make([]string, 0)
	for _, hash := range hashes {
		if !contains(urls, hash) {
			newhashs = append(newhashs, hash)
		}
	}
	hashes = RemoveDuplicates(newhashs)
	return hashes
}

// 使用正则表达式从文章中提取邮件地址域名，程序去掉邮件后缀域名的提取
func ExtractOriginEmails(content string) []string {
	var emails, emailDomain []string
	// 定义电子邮件的正则表达式
	// goodsupport@cock[.]li
	emailRegex := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+(\[\.\]|\[\.|\.|\.\])[a-zA-Z]{2,}`)
	// 查找所有匹配的邮件地址
	emails = emailRegex.FindAllString(content, -1)
	if len(emails) > 0 {
		for _, v := range emails {
			tmpD := strings.Split(v, "@")
			if len(tmpD) == 2 {
				emailDomain = append(emailDomain, tmpD[1])
			}
		}
		return emailDomain
	}
	return emailDomain
}

// 使用正则表达式从文章中提取邮件地址域名，程序去掉邮件后缀域名的提取
func ExtractEmails(content string) []string {
	emails := ExtractOriginEmails(content)
	return ClearIoc(emails)
}

// 检查字符串切片中是否包含特定的字符串
func contains(slice []string, str string) bool {
	for _, v := range slice {
		if v == str {
			return true
		}
	}
	return false
}

func ClearIoc(iocs []string) []string {
	var clearedIocs []string
	for _, ioc := range iocs {
		ioc = strings.ReplaceAll(ioc, "[.]", ".")
		ioc = strings.ReplaceAll(ioc, ".]", ".")
		ioc = strings.ReplaceAll(ioc, "[.", ".")
		ioc = replaceWithCase(ioc, "hxxp", "http")
		ioc = strings.TrimSpace(ioc)
		clearedIocs = append(clearedIocs, ioc)
	}
	clearedIocs = RemoveDuplicates(clearedIocs)
	return clearedIocs
}

// 数组去重
func RemoveDuplicates(nums []string) []string {
	encountered := map[string]bool{}
	result := []string{}

	for v := range nums {
		if encountered[nums[v]] {
			// 已经遇到过这个元素，跳过
			continue
		} else {
			// 将该元素添加到结果数组中，并将其标记为已遇到
			encountered[nums[v]] = true
			result = append(result, nums[v])
		}
	}

	return result
}

// 忽略大小写的字符串替换，并保持原大小写情况
func replaceWithCase(s, old, new string) string {
	// 使用正则表达式匹配忽略大小写的模式
	re := regexp.MustCompile("(?i)" + old)
	return re.ReplaceAllStringFunc(s, func(match string) string {
		// 保持原字符串的大小写
		if strings.ToUpper(match) == match {
			return strings.ToUpper(new)
		} else if strings.ToLower(match) == match {
			return strings.ToLower(new)
		}
		return new
	})
}
