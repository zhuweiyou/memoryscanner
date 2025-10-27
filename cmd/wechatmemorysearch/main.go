package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/zhuweiyou/memoryscanner"
)

const (
	logFilePrefix = "wechatmemorysearch"
)

func main() {
	fmt.Println("=== WeChatAppEx.exe 内存搜索工具 ===")
	fmt.Println()

	// 获取用户输入
	reader := bufio.NewReader(os.Stdin)

	// 第一次询问：搜索字符串
	fmt.Print("请输入要搜索的字符串 (支持?模糊搜索，例如we?ha?): ")
	searchStr, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("读取输入失败: %v\n", err)
		return
	}

	searchStr = strings.TrimSpace(searchStr)
	if searchStr == "" {
		fmt.Println("搜索字符串不能为空，程序退出")
		return
	}

	// 第二次询问：字节长度
	fmt.Print("请输入要搜索的字节长度 (默认1024): ")
	lengthStr, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("读取输入失败: %v\n", err)
		return
	}

	lengthStr = strings.TrimSpace(lengthStr)
	searchLength := 1024 // 默认值
	if lengthStr != "" {
		var length int
		_, err := fmt.Sscanf(lengthStr, "%d", &length)
		if err != nil || length <= 0 {
			fmt.Println("字节长度必须是正整数，程序退出")
			return
		}
		searchLength = length
	}

	fmt.Printf("开始搜索字符串: '%s' (长度: %d)\n", searchStr, searchLength)
	fmt.Println("按 Ctrl+C 可以随时停止搜索...")
	fmt.Println()

	// 设置日志文件
	logFile, err := setupLogFile()
	if err != nil {
		log.Printf("警告: 无法创建日志文件: %v", err)
	} else {
		defer logFile.Close()
		log.SetOutput(logFile)
		log.Printf("=== 搜索开始于 %s ===", time.Now().Format("2006-01-02 15:04:05"))
		log.Printf("搜索字符串: '%s' (长度: %d)", searchStr, searchLength)
	}

	// 搜索所有 WeChatAppEx.exe 进程
	fmt.Println("正在搜索 WeChatAppEx.exe 进程...")
	pids, err := memoryscanner.FindProcessesByName("WeChatAppEx.exe")
	if err != nil {
		fmt.Printf("未找到 WeChatAppEx.exe 进程: %v\n", err)
		log.Printf("未找到 WeChatAppEx.exe 进程: %v", err)
		return
	}

	if len(pids) == 0 {
		fmt.Println("未找到 WeChatAppEx.exe 进程")
		log.Println("未找到 WeChatAppEx.exe 进程")
		return
	}

	fmt.Printf("找到 %d 个 WeChatAppEx.exe 进程: %v\n", len(pids), pids)
	log.Printf("找到 %d 个 WeChatAppEx.exe 进程: %v", len(pids), pids)
	fmt.Println()

	// 设置信号处理
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		fmt.Printf("\n收到信号 %v，正在停止搜索...\n", sig)
		log.Printf("收到信号 %v，停止搜索", sig)
		cancel()
	}()

	// 开始搜索
	totalMatches := 0
	pattern := memoryscanner.StringToPattern(searchStr, searchLength)

	for _, pid := range pids {
		select {
		case <-ctx.Done():
			goto done
		default:
		}

		fmt.Printf("正在扫描进程 %d...\n", pid)
		log.Printf("开始扫描进程 %d", pid)

		matches, err := scanProcess(ctx, pid, pattern)
		if err != nil {
			fmt.Printf("扫描进程 %d 失败: %v\n", pid, err)
			log.Printf("扫描进程 %d 失败: %v", pid, err)
			continue
		}

		if len(matches) == 0 {
			fmt.Printf("进程 %d 中未找到匹配项\n", pid)
			log.Printf("进程 %d 中未找到匹配项", pid)
		} else {
			fmt.Printf("进程 %d 中找到 %d 个匹配项:\n", pid, len(matches))
			log.Printf("进程 %d 中找到 %d 个匹配项", pid, len(matches))

			for i, match := range matches {
				content := match.Content()

				// 控制台只显示前10个结果
				if i < 10 {
					displayContent := formatForConsole(content, 50)
					fmt.Printf("  [%d] 地址: %s, 内容: '%s'\n", i+1, match.Address.String(), displayContent)
				}

				// 日志记录所有结果
				log.Printf("  [%d] 地址: %s, 内容: %s", i+1, match.Address.String(), content)
			}

			// 控制台提示还有更多结果
			if len(matches) > 10 {
				fmt.Printf("  ... (还有 %d 个结果未显示，详见日志文件)\n", len(matches)-10)
			}
		}

		totalMatches += len(matches)
		fmt.Println()
	}

done:
	fmt.Printf("搜索完成！总共找到 %d 个匹配项\n", totalMatches)
	log.Printf("搜索完成！总共找到 %d 个匹配项", totalMatches)
	if logFile != nil {
		log.Printf("=== 搜索结束于 %s ===\n", time.Now().Format("2006-01-02 15:04:05"))
	}
}

// setupLogFile 创建日志文件
func setupLogFile() (*os.File, error) {
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	logFileName := fmt.Sprintf("%s_%s.log", logFilePrefix, timestamp)

	file, err := os.OpenFile(logFileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}

	return file, nil
}

// scanProcess 扫描单个进程的内存
func scanProcess(ctx context.Context, pid uint32, pattern string) ([]memoryscanner.Match, error) {
	scanner, err := memoryscanner.NewScanner(pid)
	if err != nil {
		return nil, fmt.Errorf("创建扫描器失败: %w", err)
	}
	defer scanner.Close()

	var matches []memoryscanner.Match
	matchCount := 0
	scanOpts := memoryscanner.ScanOptions{
		Pattern:    pattern,
		IgnoreCase: true,
		MinAddress: 0x0,
		MaxAddress: 0x7FFFFFFFFFFF,
		Handler: func(match memoryscanner.Match) bool {
			matches = append(matches, match)
			matchCount++

			// 实时显示进度，每100个匹配项显示一次
			if matchCount%100 == 0 {
				fmt.Printf("\r进程 %d 已找到 %d 个匹配项...", pid, matchCount)
			}

			return true
		},
	}

	err = scanner.Scan(ctx, scanOpts)
	if err != nil {
		if err == context.Canceled {
			return matches, nil
		}
		return matches, fmt.Errorf("扫描失败: %w", err)
	}

	// 如果有进度显示，换行
	if matchCount >= 100 {
		fmt.Println()
	}

	return matches, nil
}

// formatForConsole 格式化字符串用于控制台显示，将换行符替换为\n并截断
func formatForConsole(s string, maxLen int) string {
	// 将换行符、回车符等替换为\n显示
	display := strings.ReplaceAll(s, "\n", "\\n")
	display = strings.ReplaceAll(display, "\r", "\\r")
	display = strings.ReplaceAll(display, "\t", "\\t")

	// 截断字符串
	return truncateString(display, maxLen)
}

// truncateString 截断字符串用于显示
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
