package xioc

import (
	"net"
	"regexp"
	"strings"
)

// IsValidSuffix 检查域名后缀是否合法
func isValidSuffix(domain string) bool {
	splitDomain := strings.Split(domain, ".")
	if len(splitDomain) < 2 {
		return false
	}
	domainSuffix := splitDomain[len(splitDomain)-1]
	for _, suffix := range DomainSuffix {
		if domainSuffix == suffix {
			return true
		}
	}
	return false
}

// 验证IOC 中域名的合法性
func VerifyIocDomain(str []string) []string {
	var res []string
	re := `^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`
	for _, v := range str {
		matched, _ := regexp.MatchString(re, v)
		if matched {
			res = append(res, v)
		}
	}
	return res
}

// 验证IOC 中IP的合法性
func VerifyIocIp(str []string) []string {
	var res []string
	for _, v := range str {
		// 使用 net.ParseIP 尝试解析 IP 地址
		parsedIP := net.ParseIP(v)
		if parsedIP == nil || v == "127.0.0.1" {
			continue
		}
		// 检查IP是否属于私有地址范围
		if parsedIP.IsPrivate() {
			continue
		}
		// 检查解析后的 IP 地址是否为 IPv4 或 IPv6
		if parsedIP.To4() != nil {
			res = append(res, v)
		} else if parsedIP.To16() != nil {
			res = append(res, v)
		}
	}
	return res
}
