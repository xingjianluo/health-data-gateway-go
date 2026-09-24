// Package audit 记录每一次访问决策与数据读取，标注策略版本，
// 支持按策略版本回放历史结论。并发写入通过互斥与单调序号保证不丢失、不覆盖。
package audit

import (
	"sync"
	"time"

	"github.com/xingjianluo/health-data-gateway-go/consent"
	"github.com/xingjianluo/health-data-gateway-go/policy"
)

// Kind 审计条目类型。
type Kind string

const (
	KindDecision Kind = "decision"  // 访问决策（允许/拒绝）
	KindDataRead Kind = "data_read" // 决策允许后的数据读取
	KindReplay   Kind = "replay"    // 历史结论回放
)

// Entry 一条不可变审计记录。
type Entry struct {
	Seq       int64     // 全局单调递增序号
	At        time.Time // 记录时刻
	AccessID  string    // 同一次访问的 decision 与其 data_read 共享
	Kind      Kind      // 条目类型
	Actor     string    // 调用方/系统入口标识
	SubjectID string    // 数据主体
	Purpose   string    // 访问用途
	Category  policy.DataCategory
	PolicyVer policy.Version // 决策依据的策略版本
	Allowed   bool           // 决策/回放结论
	Reason    consent.Reason // 拒绝原因码（允许时为空）
	Detail    string         // 判定依据（可解释）
	Fields    []string       // data_read：实际返回的字段
	Warnings  []string       // data_read/replay：降级痕迹或比对说明
	Replayed  bool           // 是否为回放产生的条目
}

// Store 审计存储（并发安全）。
// 所有写操作在同一把锁内完成"序号分配 + 追加"，保证并发写入
// 既不会丢条目，也不会相互覆盖序号。
type Store struct {
	mu      sync.Mutex
	seq     int64
	entries []Entry
}

// NewStore 创建空审计存储。
func NewStore() *Store { return &Store{} }

// Append 追加一条审计记录，自动分配单调序号与时间戳并返回完整条目。
func (s *Store) Append(e Entry) Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	e.Seq = s.seq
	if e.At.IsZero() {
		e.At = time.Now()
	}
	if e.Fields != nil {
		e.Fields = append([]string(nil), e.Fields...)
	}
	if e.Warnings != nil {
		e.Warnings = append([]string(nil), e.Warnings...)
	}
	s.entries = append(s.entries, e)
	return e
}

// All 返回全部审计记录（按序号升序）。
func (s *Store) All() []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Entry, len(s.entries))
	copy(out, s.entries)
	return out
}

// ByAccess 返回某次访问关联的全部条目（按序号升序）。
func (s *Store) ByAccess(accessID string) []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Entry
	for _, e := range s.entries {
		if e.AccessID == accessID {
			out = append(out, e)
		}
	}
	return out
}

// LastDecision 返回某访问 ID 的决策条目（用于回放取请求快照）。
func (s *Store) LastDecision(accessID string) (Entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.entries) - 1; i >= 0; i-- {
		e := s.entries[i]
		if e.AccessID == accessID && e.Kind == KindDecision {
			return e, true
		}
	}
	return Entry{}, false
}

// Count 返回条目总数。
func (s *Store) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}
