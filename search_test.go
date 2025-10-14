package memoryscanner

import (
	"context"
	"testing"
	"time"
)

func TestFindProcessesByName(t *testing.T) {
	// 测试查找WeChatAppEx.exe进程
	pids, err := FindProcessesByName("WeChatAppEx.exe")
	if err != nil {
		t.Logf("未找到WeChatAppEx.exe进程，这是正常的: %v", err)
		return
	}

	if len(pids) == 0 {
		t.Log("未找到WeChatAppEx.exe进程")
		return
	}

	t.Logf("找到 %d 个WeChatAppEx.exe进程: %v", len(pids), pids)
}

func TestStringToPattern(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		length   int
		expected string
	}{
		{
			name:     "basic string",
			input:    "WeChat",
			length:   6,
			expected: "57 65 43 68 61 74",
		},
		{
			name:     "string with padding",
			input:    "WeChat",
			length:   10,
			expected: "57 65 43 68 61 74 ?? ?? ?? ??",
		},
		{
			name:     "string with wildcard",
			input:    "We?Chat",
			length:   7,
			expected: "57 65 ?? 43 68 61 74",
		},
		{
			name:     "empty string",
			input:    "",
			length:   5,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := StringToPattern(tt.input, tt.length)
			if result != tt.expected {
				t.Errorf("StringToPattern(%q, %d) = %q, want %q", tt.input, tt.length, result, tt.expected)
			}
		})
	}
}

func TestPatternMatcher(t *testing.T) {
	// 测试模式匹配器
	pattern := "57 65 43 68 61 74"
	matcher, err := NewPatternMatcher(pattern)
	if err != nil {
		t.Fatalf("NewPatternMatcher failed: %v", err)
	}

	// 测试数据
	testData := []byte("Hello WeChat World")
	matches := matcher.FindMatches(testData, false)

	if len(matches) != 1 {
		t.Errorf("Expected 1 match, got %d", len(matches))
	}

	if len(matches) > 0 && matches[0] != 6 {
		t.Errorf("Expected match at position 6, got %d", matches[0])
	}

	// 测试大小写不敏感
	matchesCase := matcher.FindMatches([]byte("Hello wechat world"), true)
	if len(matchesCase) != 1 {
		t.Errorf("Expected 1 case-insensitive match, got %d", len(matchesCase))
	}
}

func TestScanner(t *testing.T) {
	// 首先查找WeChatAppEx.exe进程
	pids, err := FindProcessesByName("WeChatAppEx.exe")
	if err != nil || len(pids) == 0 {
		t.Skip("跳过内存扫描测试：未找到WeChatAppEx.exe进程")
	}

	// 使用第一个进程进行测试
	pid := pids[0]
	t.Logf("测试进程 PID: %d", pid)

	// 创建扫描器
	scanner, err := NewScanner(pid)
	if err != nil {
		t.Fatalf("NewScanner failed: %v", err)
	}
	defer scanner.Close()

	// 测试搜索字符串
	searchStr := "WeChat"
	pattern := StringToPattern(searchStr, 6)

	// 创建带超时的上下文
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 计数器
	matchCount := 0

	// 设置扫描选项
	scanOpts := ScanOptions{
		Pattern:    pattern,
		IgnoreCase: true,
		MinAddress: 0x0,
		MaxAddress: 0x7FFFFFFFFFFF,
		Handler: func(match Match) bool {
			matchCount++
			t.Logf("找到匹配 #%d: 地址=%s, 内容=%s",
				matchCount,
				match.Address.String(),
				truncateStringForTest(match.Content(), 30))

			// 限制输出数量，避免测试时输出过多
			return matchCount < 10
		},
	}

	// 开始扫描
	startTime := time.Now()
	err = scanner.Scan(ctx, scanOpts)
	duration := time.Since(startTime)

	if err != nil {
		if err == context.DeadlineExceeded {
			t.Logf("扫描超时 (%.2f秒)", duration.Seconds())
		} else {
			t.Errorf("扫描出错: %v", err)
		}
	}

	t.Logf("扫描完成，用时: %.2f秒，找到 %d 个匹配", duration.Seconds(), matchCount)

	if matchCount == 0 {
		t.Log("未找到匹配项，这可能是因为搜索字符串不在进程内存中")
	}
}

func TestAddressString(t *testing.T) {
	tests := []struct {
		input    Address
		expected string
	}{
		{0x0, "0x0"},
		{0x1234, "0x1234"},
		{0x7FFFFFFFFFFF, "0x7FFFFFFFFFFF"},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			result := tt.input.String()
			if result != tt.expected {
				t.Errorf("Address(%d).String() = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestMatchContent(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name:     "valid UTF-8",
			data:     []byte("Hello World"),
			expected: "Hello World",
		},
		{
			name:     "empty data",
			data:     []byte{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match := Match{Data: tt.data}
			result := match.Content()
			if result != tt.expected {
				t.Errorf("Match.Content() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// 辅助函数：截断字符串用于测试显示
func truncateStringForTest(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// 基准测试：模式匹配性能
func BenchmarkPatternMatcher(b *testing.B) {
	pattern := "57 65 43 68 61 74"
	matcher, err := NewPatternMatcher(pattern)
	if err != nil {
		b.Fatalf("NewPatternMatcher failed: %v", err)
	}

	// 创建测试数据 (1KB)
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matcher.FindMatches(data, false)
	}
}