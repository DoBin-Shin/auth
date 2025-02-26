package crypto

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

const (
	SHA512Prefix = "$sha512$"
	saltLength   = 32  // 더 긴 솔트 길이
	iterations   = 10000
)

// SecureRandomBytes generates cryptographically secure random bytes
func SecureRandomBytes(length int) ([]byte, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	return b, err
}

// GenerateFromPassword creates a secure SHA-512 hash
func GenerateFromPassword(ctx context.Context, password string) (string, error) {
	// 솔트 생성
	salt, err := SecureRandomBytes(saltLength)
	if err != nil {
		return "", err
	}

	// 비밀번호 해시
	hash := sha512Hash([]byte(password), salt, iterations)

	// 포맷: $sha512$iterations$salt$hash
	return fmt.Sprintf("%s%d$%s$%s", 
		SHA512Prefix, 
		iterations, 
		base64.RawStdEncoding.EncodeToString(salt), 
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// CompareHashAndPassword verifies a password against its hash
func CompareHashAndPassword(ctx context.Context, hash, password string) error {
	// SHA-512 해시 형식 확인
	if !strings.HasPrefix(hash, SHA512Prefix) {
		return errors.New("invalid hash format")
	}

	// 해시 구성 요소 분리
	parts := strings.Split(hash[len(SHA512Prefix):], "$")
	if len(parts) != 3 {
		return errors.New("invalid hash format")
	}

	// 반복 횟수 추출
	iters, err := strconv.Atoi(parts[0])
	if err != nil {
		return errors.New("invalid iterations")
	}

	// 솔트 디코딩
	salt, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return errors.New("invalid salt")
	}

	// 원본 해시 디코딩
	originalHash, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return errors.New("invalid hash")
	}

	// 입력된 비밀번호로 해시 재생성
	computedHash := sha512Hash([]byte(password), salt, iters)

	// 안전한 상수 시간 비교
	if subtle.ConstantTimeCompare(computedHash, originalHash) != 1 {
		return errors.New("password mismatch")
	}

	return nil
}

// sha512Hash performs multiple iterations of SHA-512 hashing with a salt
func sha512Hash(password, salt []byte, iterations int) []byte {
	hash := append(password, salt...)
	for i := 0; i < iterations; i++ {
		hasher := sha512.New()
		hasher.Write(hash)
		hash = hasher.Sum(nil)
	}
	return hash
}

// GeneratePassword creates a secure random password
func GeneratePassword(requiredChars []string, length int) string {
	passwordBuilder := strings.Builder{}
	passwordBuilder.Grow(length)

	// 필수 문자 추가
	for _, group := range requiredChars {
		if len(group) > 0 {
			randomIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(len(group))))
			passwordBuilder.WriteByte(group[randomIndex.Int64()])
		}
	}

	// 기본 문자 세트
	const allChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+"

	// 비밀번호 나머지 부분 채우기
	for passwordBuilder.Len() < length {
		randomIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(len(allChars))))
		passwordBuilder.WriteByte(allChars[randomIndex.Int64()])
	}

	// 비밀번호 섞기
	passwordBytes := []byte(passwordBuilder.String())
	for i := len(passwordBytes) - 1; i > 0; i-- {
		randomIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		j := randomIndex.Int64()
		passwordBytes[i], passwordBytes[j] = passwordBytes[j], passwordBytes[i]
	}

	return string(passwordBytes)
}

// SecureToken creates a new secure random token
func SecureToken() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// 보조 함수들 (기존 구현 유지)
func GenerateOtp(digits int) string {
	upper := big.NewInt(int64(10 * digits))
	val, _ := rand.Int(rand.Reader, upper)
	return fmt.Sprintf("%0*d", digits, val)
}

func GenerateTokenHash(emailOrPhone, otp string) string {
	hasher := sha512.New()
	hasher.Write([]byte(emailOrPhone + otp))
	return hex.EncodeToString(hasher.Sum(nil))
}

func secureRandomInt(max int) int { 
	randomInt, _ := rand.Int(rand.Reader, big.NewInt(int64(max))) 
	return int(randomInt.Int64()) 
}