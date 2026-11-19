package agent

func itoa(n int64) string {
	b := []byte{}
	neg := n < 0
	if neg {
		n = -n
	}
	for {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
		if n == 0 {
			break
		}
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
