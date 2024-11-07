package main

import (
	"crypto/hmac"
	"crypto/sha1"
	_ "embed"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"
)

func main() {
	// 打开配置文件
	file, err := os.Open("config.yml")
	if err != nil {
		log.Fatalf("无法打开文件: %v", err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.Fatalf("无法关闭文件: %v", err)
		}
	}(file)

	// 读取文件内容
	data, err := io.ReadAll(file)
	if err != nil {
		log.Fatalf("无法读取文件: %v", err)
	}

	//读取配置项
	var configs []string
	content := string(data)
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		configs = append(configs, line)
	}

	for {
		var results []map[string]int64
		fmtStr := "\r%s"
		now := time.Now().Format("2006-01-02 15:04:05")
		args := []interface{}{now}
		for _, config := range configs {
			kv := strings.Split(config, ": ")
			if len(kv) != 2 {
				log.Fatalf("配置文件错误，请检查配置文件是否以【key: value】的方式定义")
			}
			totp, err := generateTOTP(kv[1], 30)
			if err != nil {
				fmt.Println("【"+kv[0]+"】TOTP认证动态口令生成失败，原因:", err)
				return
			}
			results = append(results, map[string]int64{kv[0]: totp})
			fmtStr += " 【" + kv[0] + "】TOTP认证动态口令: %06d"
			args = append(args, totp)
		}
		fmt.Printf(fmtStr, args...)
		time.Sleep(time.Second)
	}
}

func generateTOTP(secret string, timeStep int64) (int64, error) {
	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return 0, err
	}
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(time.Now().Unix()/timeStep))
	hash := hmac.New(sha1.New, key)
	hash.Write(b)
	digest := hash.Sum(nil)
	offset := digest[len(digest)-1] & 0xf
	truncatedHash := digest[offset : offset+4]
	code := int64((binary.BigEndian.Uint32(truncatedHash) & 0x7fffffff) % 1000000)
	return code, nil
}
