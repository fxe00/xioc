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

func (ioc Iocs)IsEmpty() bool {
	if len(ioc.Domains) == 0 && len(ioc.Ips) == 0 && len(ioc.Urls) == 0 && len(ioc.Hashs) == 0 && len(ioc.Emails) == 0 {
		return true
	}
	return false
}

// 从文章中提取出ioc
func ExtractIocs(content string) Iocs {
	var iocs Iocs
	iocs.Domains = ExtractDomains(content)
	iocs.Ips = ExtractIPs(content)
	iocs.Urls = ExtractUrls(content)
	iocs.Hashs = ExtractHashs(content)
	iocs.Emails = ExtractEmails(content)
	return iocs
}

// 使用正则表达式从文章中提取域名
func ExtractDomains(content string) []string {
	//domainRegex := regexp.MustCompile(`(?i)(?P<domain>[a-zA-Z0-9-]+\.[a-zA-Z]+)`)
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
	// 建议域名是否合法，输出合法的后缀域名
	if len(uniqueDomains) > 0 {
		for _, v := range uniqueDomains {
			var tmpV string
			// 增加域名中[.] 或 [. 或 .] 匹配
			if strings.Contains(v, "[.") || strings.Contains(v, ".]") {
				tmpV = strings.ReplaceAll(v, "[.]", ".")
				tmpV = strings.ReplaceAll(tmpV, ".]", ".")
				tmpV = strings.ReplaceAll(tmpV, "[.", ".")
			} else {
				tmpV = v
			}
			tmpV = strings.TrimSpace(tmpV)
			if isValidSuffix(tmpV) {
				validDomains = append(validDomains, tmpV)
			}
		}
		return validDomains
	}
	return uniqueDomains
}

// 使用正则表达式从文章中提取IP地址
func ExtractIPs(content string) []string {
	//ipRegex := regexp.MustCompile(`(?i)(?:\d{1,3}\.){3}\d{1,3}`)
	ipRegex := regexp.MustCompile(`(?i)(?:\d{1,3}(?:\[\.]|\.|\[\.|\.\])?){3}\d{1,3}`)
	ips := ipRegex.FindAllString(content, -1)
	// 验证IP地址的合法性
	if len(ips) == 0 {
		return []string{}
	} else {
		ips = VerifyIocIp(ips)
	}
	var validIps []string
	for _, v := range ips { // 处理不符合格式的IP地址：.、[.]、[. 或 . ]
		var tmpV string
		if strings.Contains(v, "[.") || strings.Contains(v, ".]") {
			tmpV = strings.ReplaceAll(v, "[.]", ".")
			tmpV = strings.ReplaceAll(tmpV, ".]", ".")
			tmpV = strings.ReplaceAll(tmpV, "[.", ".")
		} else {
			tmpV = v
		}
		validIps = append(validIps, strings.TrimSpace(tmpV))
	}
	ips = RemoveDuplicates(validIps)
	return ips
}

// 使用正则表达式从文章中提取URL
func ExtractUrls(content string) []string {
	var rep = []string{
		"https",
		"http",
		"hxxps",
		"hxxp",
	}
	var urls []string
	for _, v := range rep {
		// 测试通过 https[:]//a13aaa1.oss-cn-hongkong.aliyuncs[.]com/hj/MEmuSVC.exe
		str := fmt.Sprintf(`(?i)%s?(\[:|\]:|\[:\]|:)//[a-zA-Z0-9-]+((\[\.\]|\[\.|\.|\.\]|\-|\/|\?|\_|\=|\_\=)+[a-zA-Z0-9-]+)+`, v)
		urlRegex := regexp.MustCompile(str)
		tmpUrls := urlRegex.FindAllString(content, -1)
		if len(tmpUrls) > 0 {
			urls = append(urls, tmpUrls...)
		}
	}
	urls = RemoveDuplicates(urls)
	return urls
}

// 使用正则表达式从文章中提取哈希值
func ExtractHashs(content string) []string {
	// 正则表达式，匹配MD5、SHA-1和SHA-256哈希值；优先匹配SHA-256，然后是SHA-1，最后是MD5
	hashRegex := regexp.MustCompile(`([a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})`)
	// 查找所有匹配的哈希值
	hashes := hashRegex.FindAllString(content, -1)
	hashes = RemoveDuplicates(hashes)
	return hashes
}

// 使用正则表达式从文章中提取邮件地址域名，程序去掉邮件后缀域名的提取
func ExtractEmails(content string) []string {
	var emails, emailDomain []string
	// 定义电子邮件的正则表达式
	emailRegex := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
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

// 检查字符串切片中是否包含特定的字符串
func contains(slice []string, str string) bool {
	for _, v := range slice {
		if v == str {
			return true
		}
	}
	return false
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
