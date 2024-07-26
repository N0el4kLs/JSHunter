package util

func LongestCommonSubstring(a, b string) (int, string) {
	m, n := len(a), len(b)
	// dp[i][j] 表示a的前i个字符和b的前j个字符的最长公共子串的长度
	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}

	// 初始长度为0的公共子串长度为1
	for i := range dp {
		dp[i][0] = 0
	}
	for j := range dp[0] {
		dp[0][j] = 0
	}

	maxLen := 0
	endIndex := 0
	// 填充dp数组
	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if a[i-1] == b[j-1] {
				dp[i][j] = dp[i-1][j-1] + 1
				if dp[i][j] > maxLen {
					maxLen = dp[i][j]
					endIndex = i
				}
			} else {
				dp[i][j] = 0
			}
		}
	}

	// 从a中获取最长公共子串
	return maxLen, a[endIndex-maxLen : endIndex]
}

func UniqueSlice(slice []string) []string {
	var (
		uniqueResult []string
		tmp          = make(map[string]struct{})
	)
	for _, v := range slice {
		if _, ok := tmp[v]; !ok {
			uniqueResult = append(uniqueResult, v)
			tmp[v] = struct{}{}
		}
	}
	return uniqueResult
}

func InSlice(s string, slice []string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
