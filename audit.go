package gateway

import (
	"sync"
	"time"
)

// AuditRecord 一次访问决策/数据读取的审计记录
type AuditRecord struct {
	ID             int64
	Timestamp      time.Time
	Entry          string // 访问入口
	SubjectID      SubjectID
	Purpose        Purpose
	Category       Category
	Requested      []FieldName
	Decision       Decision
	FieldsReturned []FieldName
	PolicyVersion  string
	Note           string
}

// AuditLog 并发安全的只追加审计日志
type AuditLog struct {
	mu      sync.Mutex
	seq     int64
	records []AuditRecord
}

func NewAuditLog() *AuditLog {
	return &AuditLog{}
}

// Append 追加一条审计记录。
// 整个 ID 分配与切片写入在同一把锁内完成，保证并发下 ID 不重复、记录不丢失、不互相覆盖。
func (l *AuditLog) Append(rec AuditRecord) AuditRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	rec.ID = l.seq
	// 拷贝切片，避免调用方后续修改影响已落盘记录
	rec.Requested = append([]FieldName(nil), rec.Requested...)
	rec.FieldsReturned = append([]FieldName(nil), rec.FieldsReturned...)
	l.records = append(l.records, rec)
	return rec
}

// Get 按 ID 读取审计记录
func (l *AuditLog) Get(id int64) (AuditRecord, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, r := range l.records {
		if r.ID == id {
			return r, true
		}
	}
	return AuditRecord{}, false
}

// List 返回全部审计记录的副本（按写入顺序）
func (l *AuditLog) List() []AuditRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	cp := make([]AuditRecord, len(l.records))
	copy(cp, l.records)
	return cp
}

// Len 返回审计记录条数
func (l *AuditLog) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.records)
}
