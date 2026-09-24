package gateway

import "sync"

// Record 某主体某类别下的一条本地健康数据（字段 -> 值）
type Record map[FieldName]string

// HealthStore 本地健康数据存储
type HealthStore struct {
	mu   sync.RWMutex
	data map[SubjectID]map[Category]Record
}

func NewHealthStore() *HealthStore {
	return &HealthStore{data: make(map[SubjectID]map[Category]Record)}
}

// Put 写入一条本地数据（按副本存储，避免外部修改）
func (s *HealthStore) Put(subject SubjectID, category Category, rec Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cats, ok := s.data[subject]
	if !ok {
		cats = make(map[Category]Record)
		s.data[subject] = cats
	}
	cp := make(Record, len(rec))
	for k, v := range rec {
		cp[k] = v
	}
	cats[category] = cp
}

// Get 读取一条本地原始数据的副本
func (s *HealthStore) Get(subject SubjectID, category Category) (Record, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cats, ok := s.data[subject]
	if !ok {
		return nil, false
	}
	rec, ok := cats[category]
	if !ok {
		return nil, false
	}
	cp := make(Record, len(rec))
	for k, v := range rec {
		cp[k] = v
	}
	return cp, true
}
