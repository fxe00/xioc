# xioc
A Go Package Extract Iocs in Article

## 引入该包
`
go get github.com/fxe00/xioc
`

## functions
```
func ExtractDomains(content string) []string
使用正则表达式从文章中提取域名

func ExtractEmails(content string) []string
使用正则表达式从文章中提取邮件地址域名，程序去掉邮件后缀域名的提取

func ExtractHashs(content string) []string
使用正则表达式从文章中提取哈希值

func ExtractIPs(content string) []string
使用正则表达式从文章中提取IP地址

func ExtractIocsList(content string) []string
从文章中提取出ioc, 无分类

func ExtractUrls(content string) []string
使用正则表达式从文章中提取URL

func RemoveDuplicates(nums []string) []string
数组去重

func VerifyIocDomain(str []string) []string
验证IOC 中域名的合法性

func VerifyIocIp(str []string) []string
验证IOC 中IP的合法性

func ExtractIocs(content string) Iocs
从文章中提取出ioc, 有分类

func (Iocs) IsEmpty
func (ioc Iocs) IsEmpty() bool
```