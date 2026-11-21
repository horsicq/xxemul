/* Private finite current-thread hook state. Included after win_api and before
 * struct xxemul_windows; Root adds `win_hook_state hooks;` to that structure. */
#define WIN_HOOK_SLOTS 64u
#define WIN_HOOK_EVENTS 16u
#define WIN_HOOK_CALLS 128u
#define WIN_HOOK_HANDLE_BASE UINT64_C(0xcb000000)
#define WIN_HOOK_HANDLE_LIMIT UINT64_C(0x00ffffff)
enum { WIN_HOOK_RESUME_API = 0u, WIN_HOOK_RESUME_WINDOW = 1u,
       WIN_HOOK_RESUME_DIALOG = 2u, WIN_HOOK_RESUME_MODAL_FILTER = 3u };
enum { WIN_HOOK_PENDING_NONE = 0u, WIN_HOOK_PENDING_NEXT = 1u,
       WIN_HOOK_PENDING_FILTER = 2u };

typedef struct win_hook_record {
    uint64_t handle, procedure, generation, sequence;
    uint32_t owner_id, references;
    int32_t id;
    uint8_t allocated, enabled, wide;
} win_hook_record;
typedef struct win_hook_token { uint64_t generation; uint16_t slot; } win_hook_token;
typedef struct win_hook_event {
    win_hook_token tokens[WIN_HOOK_SLOTS];
    uint64_t sequence, creator_sequence;
    uint32_t owner_id, creator_slot, resume_kind, calls;
    int32_t id;
    uint16_t count;
    uint8_t active, wide;
} win_hook_event;
typedef struct win_hook_call {
    xxemul_x86_state caller;
    uint64_t sequence, event_sequence, hook_generation, call_sp, wparam, lparam;
    uint32_t owner_id, mxcsr;
    int32_t code;
    uint16_t event_slot, current_index, start_index, hook_slot, control;
    uint8_t active, root, invoking;
} win_hook_call;
typedef struct win_hook_pending {
    uint32_t owner_id;
    uint64_t wparam, lparam;
    int32_t code;
    uint16_t call_slot;
    uint8_t kind, wide;
} win_hook_pending;
typedef struct win_hook_state {
    win_hook_record records[WIN_HOOK_SLOTS];
    win_hook_event events[WIN_HOOK_EVENTS];
    win_hook_call calls[WIN_HOOK_CALLS];
    win_hook_pending pending[WIN_MAX_THREADS];
    uint64_t handle_sequence, registration_sequence, event_sequence, call_sequence;
} win_hook_state;

static int win_cbt_api(xxemul_windows *, const win_api *, const uint64_t *,
                       uint64_t *, xxemul_status *);
static int win_cbt_api_pending(const xxemul_windows *);
static xxemul_status win_cbt_api_continue(xxemul_windows *, xxemul_step_info *);
static xxemul_status win_hook_begin(xxemul_windows *, int, int, uint64_t,
                                   uint64_t, int, unsigned, unsigned, uint64_t,
                                   xxemul_step_info *);
static xxemul_status win_cbt_begin(xxemul_windows *, int, uint64_t, uint64_t,
                                  int, unsigned, unsigned, uint64_t,
                                  xxemul_step_info *);
static xxemul_status win_msgfilter_begin(xxemul_windows *, int, uint64_t,
                                        uint64_t, int, unsigned, unsigned,
                                        uint64_t, xxemul_step_info *);
static xxemul_status win_cbt_return(xxemul_windows *, xxemul_step_info *);
static xxemul_status win_cbt_event_supported(xxemul_windows *, int, int);
static xxemul_status win_msgfilter_event_supported(xxemul_windows *, int, int);
static void win_cbt_abandon_thread(xxemul_windows *, uint32_t);
/* Root-owned, called only after restoring the saved creator's actual CPU. */
static xxemul_status win_cbt_creator_resume(xxemul_windows *, unsigned, unsigned,
                                           uint64_t, uint64_t,
                                           xxemul_step_info *);
