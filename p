From e7aa532de5fe3050ae12eae66afb7316bcb8a034 Mon Sep 17 00:00:00 2001
From: Puranjay Mohan <puranjay@kernel.org>
To: Alexei Starovoitov <ast@kernel.org>,Daniel Borkmann <daniel@iogearbox.net>,Andrii Nakryiko <andrii@kernel.org>,Martin KaFai Lau <martin.lau@linux.dev>,Eduard Zingerman <eddyz87@gmail.com>,Song Liu <song@kernel.org>,Yonghong Song <yonghong.song@linux.dev>,John Fastabend <john.fastabend@gmail.com>,KP Singh <kpsingh@kernel.org>,Stanislav Fomichev <sdf@fomichev.me>,Hao Luo <haoluo@google.com>,Jiri Olsa <jolsa@kernel.org>,Puranjay Mohan <puranjay12@gmail.com>,Xu Kuohai <xukuohai@huaweicloud.com>,Catalin Marinas <catalin.marinas@arm.com>,Will Deacon <will@kernel.org>,Jean-Philippe Brucker <jean-philippe@linaro.org>,bpf@vger.kernel.org,linux-arm-kernel@lists.infradead.org,linux-kernel@vger.kernel.org
Date: Thu, 11 Jul 2024 14:38:10 +0000
Subject: [PATCH bpf] bpf, arm64: fix trampoline for BPF_TRAMP_F_CALL_ORIG

When BPF_TRAMP_F_CALL_ORIG is set, the trampoline calls
__bpf_tramp_enter() and __bpf_tramp_exit() functions, passing them the
struct bpf_tramp_image *im pointer as an argument in R0.

The trampoline generation code uses emit_addr_mov_i64() to emit
instructions for moving the bpf_tramp_image address into R0, but
emit_addr_mov_i64() assumes the address to be in the vmalloc() space and
uses only 48 bits. Because bpf_tramp_image is allocated using kzalloc(),
its address can use more than 48-bits, in this case the trampoline
will pass an invalid address to __bpf_tramp_enter/exit() causing a
kernel crash.

Fix this by using emit_a64_mov_i64() in place of emit_addr_mov_i64() as
it can work with addresses that are greater than 48-bits.

Fixes: efc9909fdce0 ("bpf, arm64: Add bpf trampoline for arm64")
Closes: https://lore.kernel.org/all/SJ0PR15MB461564D3F7E7A763498CA6A8CBDB2@SJ0PR15MB4615.namprd15.prod.outlook.com/
Signed-off-by: Puranjay Mohan <puranjay@kernel.org>
---
 arch/arm64/net/bpf_jit_comp.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/arch/arm64/net/bpf_jit_comp.c b/arch/arm64/net/bpf_jit_comp.c
index 720336d28856..1bf483ec971d 100644
--- a/arch/arm64/net/bpf_jit_comp.c
+++ b/arch/arm64/net/bpf_jit_comp.c
@@ -2141,7 +2141,7 @@ static int prepare_trampoline(struct jit_ctx *ctx, struct bpf_tramp_image *im,
 	emit(A64_STR64I(A64_R(20), A64_SP, regs_off + 8), ctx);
 
 	if (flags & BPF_TRAMP_F_CALL_ORIG) {
-		emit_addr_mov_i64(A64_R(0), (const u64)im, ctx);
+		emit_a64_mov_i64(A64_R(0), (const u64)im, ctx);
 		emit_call((const u64)__bpf_tramp_enter, ctx);
 	}
 
@@ -2185,7 +2185,7 @@ static int prepare_trampoline(struct jit_ctx *ctx, struct bpf_tramp_image *im,
 
 	if (flags & BPF_TRAMP_F_CALL_ORIG) {
 		im->ip_epilogue = ctx->ro_image + ctx->idx;
-		emit_addr_mov_i64(A64_R(0), (const u64)im, ctx);
+		emit_a64_mov_i64(A64_R(0), (const u64)im, ctx);
 		emit_call((const u64)__bpf_tramp_exit, ctx);
 	}
 
-- 
2.40.1

