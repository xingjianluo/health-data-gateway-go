package gateway

import "sync"

// idempotencyRegistry 批量请求幂等登记表。
// 相同幂等键的重试/断点重跑直接返回首次结论：不重复判定、不重复读取数据、不重复写审计。
type idempotencyRegistry struct {
	mu      sync.Mutex
	pending map[string]struct{}
	done    map[string]BatchResponse
}

func newIdempotencyRegistry() *idempotencyRegistry {
	return &idempotencyRegistry{
		pending: make(map[string]struct{}),
		done:    make(map[string]BatchResponse),
	}
}

// begin 登记一个键。返回 finished 时：
//   - cached 非空：该键已有最终结论，调用方必须原样返回，不得再次处理；
//   - acquire 为 true：本调用获得首次处理权，处理完成后必须调用 finish 落定结论；
//   - acquire 为 false 且 cached 为空：同一键正在被其他调用处理，本调用需等待后重试读取。
func (r *idempotencyRegistry) begin(key string) (cached BatchResponse, acquire bool) {
	if key == "" {
		// 未提供幂等键的请求不参与去重，每次都独立处理
		return BatchResponse{}, true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if resp, ok := r.done[key]; ok {
		return resp, false
	}
	if _, busy := r.pending[key]; busy {
		return BatchResponse{}, false
	}
	r.pending[key] = struct{}{}
	return BatchResponse{}, true
}

// wait 等待一个正在处理中的键落定，返回最终结论；未提供键或等待不到时返回 false。
func (r *idempotencyRegistry) wait(key string) (BatchResponse, bool) {
	if key == "" {
		return BatchResponse{}, false
	}
	for {
		r.mu.Lock()
		if resp, ok := r.done[key]; ok {
			r.mu.Unlock()
			return resp, true
		}
		_, busy := r.pending[key]
		r.mu.Unlock()
		if !busy {
			return BatchResponse{}, false
		}
	}
}

// finish 落定首次处理的结论，并解除占用。空键为空操作。
func (r *idempotencyRegistry) finish(key string, resp BatchResponse) {
	if key == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.pending, key)
	r.done[key] = resp
}
