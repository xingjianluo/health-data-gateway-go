// Package storage 提供本地健康数据存储，模拟受保护的后端数据源。
package storage

import (
	"errors"
	"sync"

	"github.com/xingjianluo/health-data-gateway-go/policy"
)

// Record 一条主体健康记录：键为字段名，值统一用字符串模拟。
type Record struct {
	SubjectID string
	Category  policy.DataCategory
	Data      map[string]string
}

// Store 本地健康记录存储（并发安全）。
type Store struct {
	mu      sync.RWMutex
	records map[string]map[policy.DataCategory]*Record // subjectID -> category -> record
}

// ErrRecordNotFound 记录不存在。
var ErrRecordNotFound = errors.New("storage: health record not found")

// NewStore 创建空的本地存储。
func NewStore() *Store {
	return &Store{records: map[string]map[policy.DataCategory]*Record{}}
}

// Seed 灌入测试种子数据（覆盖已有同主键记录）。
func (s *Store) Seed(records ...Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range records {
		if _, ok := s.records[r.SubjectID]; !ok {
			s.records[r.SubjectID] = map[policy.DataCategory]*Record{}
		}
		cp := Record{
			SubjectID: r.SubjectID,
			Category:  r.Category,
			Data:      make(map[string]string, len(r.Data)),
		}
		for k, v := range r.Data {
			cp.Data[k] = v
		}
		s.records[r.SubjectID][r.Category] = &cp
	}
}

// Get 读取某主体某类别的原始健康记录。
// 返回副本，调用方修改不会污染存储。
func (s *Store) Get(subjectID string, cat policy.DataCategory) (*Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cats, ok := s.records[subjectID]
	if !ok {
		return nil, ErrRecordNotFound
	}
	r, ok := cats[cat]
	if !ok {
		return nil, ErrRecordNotFound
	}
	cp := &Record{
		SubjectID: r.SubjectID,
		Category:  r.Category,
		Data:      make(map[string]string, len(r.Data)),
	}
	for k, v := range r.Data {
		cp.Data[k] = v
	}
	return cp, nil
}
