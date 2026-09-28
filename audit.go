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
	// BatchID 关联的整批审计记录 ID；单主体访问为 0
	BatchID int64
	// Degraded 是否为降级放行（允许返回但有字段被跳过）
	Degraded bool
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

// ListByBatch 返回关联到指定整批记录的逐条审计（按审计 ID 顺序）。
// 用于把整批请求与每个主体的输入、判定依据、实际返回范围及拒/降级原因关联核对。
func (l *AuditLog) ListByBatch(batchID int64) []AuditRecord {
	if batchID <= 0 {
		// 0 是单主体访问的占位值，不能把单主体审计算作某一批次
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []AuditRecord
	for _, r := range l.records {
		if r.BatchID == batchID {
			cp := r
			cp.Requested = append([]FieldName(nil), r.Requested...)
			cp.FieldsReturned = append([]FieldName(nil), r.FieldsReturned...)
			out = append(out, cp)
		}
	}
	return out
}

// Len 返回审计记录条数
func (l *AuditLog) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.records)
}

// ---- 整批审计 ----

// batchEntry 整批审计日志内部条目
type batchEntry struct {
	rec   BatchRecord
	done  chan struct{} // 已关闭表示结论已提交；nil 表示尚未登记
	ready bool
}

// BatchLog 并发安全的整批审计与幂等登记表。
// 它同时承担两件事：
//  1. 幂等登记：按 IdempotencyKey 保证同键只有一个批次真正执行，
//     并发/重试的同键调用等待首个批次的结论并拿到完全一致的返回；
//  2. 不可变快照：整批结论一旦 Commit 即固定，之后同意撤回、策略更新、
//     再次重试都不能改写该批已经确定的结论（回放依据）。
type BatchLog struct {
	mu      sync.Mutex
	seq     int64
	records []BatchRecord
	byKey   map[string]*batchEntry
}

func NewBatchLog() *BatchLog {
	return &BatchLog{byKey: make(map[string]*batchEntry)}
}

// Claim 按幂等键登记一个批次。
//   - 同键已存在：返回该条目与 execute=false，调用方应等待 done 并读取既有结论；
//   - 同键首次出现：原子地分配 BatchID、登记 done channel 并返回 execute=true，
//     只有拿到 execute=true 的调用方执行实际读取与逐条审计，然后必须 Commit。
//
// key 为空时不做幂等去重，每次都分配新 BatchID（execute 恒为 true，done 为 nil）。
func (l *BatchLog) Claim(key string) (id int64, done <-chan struct{}, execute bool) {
	if key == "" {
		l.mu.Lock()
		l.seq++
		id = l.seq
		l.mu.Unlock()
		return id, nil, true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if e, ok := l.byKey[key]; ok {
		return e.rec.BatchID, e.done, false
	}
	l.seq++
	id = l.seq
	e := &batchEntry{
		rec:  BatchRecord{BatchID: id, IdempotencyKey: key},
		done: make(chan struct{}),
	}
	l.byKey[key] = e
	return id, e.done, true
}

// Commit 提交整批不可变快照并放行所有等待同键结果的调用方。
func (l *BatchLog) Commit(rec BatchRecord) {
	l.mu.Lock()
	defer l.mu.Unlock()
	saved := cloneBatchRecord(rec)
	var e *batchEntry
	if saved.IdempotencyKey != "" {
		e = l.byKey[saved.IdempotencyKey]
	}
	if e != nil {
		e.rec = saved
		e.ready = true
		close(e.done)
	}
	l.records = append(l.records, saved)
}

// Get 按 BatchID 读取整批快照副本
func (l *BatchLog) Get(id int64) (BatchRecord, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, r := range l.records {
		if r.BatchID == id {
			return cloneBatchRecord(r), true
		}
	}
	return BatchRecord{}, false
}

// GetByKey 按幂等键读取已提交的整批快照；未提交时返回 false
func (l *BatchLog) GetByKey(key string) (BatchRecord, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.byKey[key]
	if !ok || !e.ready {
		return BatchRecord{}, false
	}
	return cloneBatchRecord(e.rec), true
}

// List 返回全部整批记录的副本（按提交顺序）
func (l *BatchLog) List() []BatchRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	cp := make([]BatchRecord, len(l.records))
	for i, r := range l.records {
		cp[i] = cloneBatchRecord(r)
	}
	return cp
}

// Len 返回整批记录条数
func (l *BatchLog) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.records)
}

func cloneRecord(rec Record) Record {
	if rec == nil {
		return nil
	}
	cp := make(Record, len(rec))
	for k, v := range rec {
		cp[k] = v
	}
	return cp
}

func cloneBatchRecord(r BatchRecord) BatchRecord {
	cp := r
	if r.Results != nil {
		cp.Results = make([]BatchSubjectRecord, len(r.Results))
		for i, s := range r.Results {
			cs := s
			cs.Record = cloneRecord(s.Record)
			cp.Results[i] = cs
		}
	}
	return cp
}
