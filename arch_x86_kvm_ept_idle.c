 // SPDX-License-Identifier: GPL-2.0
 #include <linux/pagemap.h>
 #include <linux/mm.h>
 #include <linux/kernel.h>
 #include <linux/sched.h>
 #include <linux/proc_fs.h>
 #include <linux/uaccess.h>
 #include <linux/kvm.h>
 #include <linux/kvm_host.h>
 #include <linux/bitmap.h>
 #include <linux/sched/mm.h>
 #include <asm/tlbflush.h>
 
 #include "ept_idle.h"
 
 /* #define DEBUG 1 */
 
 #ifdef DEBUG
 
 #define debug_printk trace_printk
 
 #define set_restart_gpa(val, note)	({			\更新eic结构体restart_gpa
 	unsigned long old_val = eic->restart_gpa;		\
 	eic->restart_gpa = (val);				\
 	trace_printk("restart_gpa=%lx %luK  %s  %s %d\n",	\
 		     (val), (eic->restart_gpa - old_val) >> 10,	\
 		     note, __func__, __LINE__);			\
 })
 
 #define set_next_hva(val, note)	({				\更新eic结构体next_hva
 	unsigned long old_val = eic->next_hva;			\
 	eic->next_hva = (val);					\
 	trace_printk("   next_hva=%lx %luK  %s  %s %d\n",	\
 		     (val), (eic->next_hva - old_val) >> 10,	\
 		     note, __func__, __LINE__);			\
 })
 
 #else
 
 #define debug_printk(...)//同上
 
 #define set_restart_gpa(val, note)	({			\
 	eic->restart_gpa = (val);				\
 })
 
 #define set_next_hva(val, note)	({				\
 	eic->next_hva = (val);					\
 })
 
 #endif
 
 static unsigned long pagetype_size[16] = {//为各种页类型赋值
 	[PTE_ACCESSED]	= PAGE_SIZE,	/* 4k page */
 	[PMD_ACCESSED]	= PMD_SIZE,	/* 2M page */
 	[PUD_PRESENT]	= PUD_SIZE,	/* 1G page */
 
 	[PTE_DIRTY]	= PAGE_SIZE,
 	[PMD_DIRTY]	= PMD_SIZE,
 
 	[PTE_IDLE]	= PAGE_SIZE,
 	[PMD_IDLE]	= PMD_SIZE,
 	[PMD_IDLE_PTES] = PMD_SIZE,
 
 	[PTE_HOLE]	= PAGE_SIZE,
 	[PMD_HOLE]	= PMD_SIZE,
 };
 
 static void u64_to_u8(uint64_t n, uint8_t *p)//64ubit转8ubit
 {
 	p += sizeof(uint64_t) - 1;
 
 	*p-- = n; n >>= 8;
 	*p-- = n; n >>= 8;
 	*p-- = n; n >>= 8;
 	*p-- = n; n >>= 8;
 
 	*p-- = n; n >>= 8;
 	*p-- = n; n >>= 8;
 	*p-- = n; n >>= 8;
 	*p   = n;
 }
 
 static void dump_eic(struct ept_idle_ctrl *eic)//输出eic结构体的值
 {
 	debug_printk("ept_idle_ctrl: pie_read=%d pie_read_max=%d buf_size=%d "
 		     "bytes_copied=%d next_hva=%lx restart_gpa=%lx "
 		     "gpa_to_hva=%lx\n",
 		     eic->pie_read,
 		     eic->pie_read_max,
 		     eic->buf_size,
 		     eic->bytes_copied,
 		     eic->next_hva,
 		     eic->restart_gpa,
 		     eic->gpa_to_hva);
 }
 
 static void eic_report_addr(struct ept_idle_ctrl *eic, unsigned long addr)//kie长度8000，更新kie当中记录的addr
 {
 	unsigned long hva;
 	eic->kpie[eic->pie_read++] = PIP_CMD_SET_HVA;//记录操作
 	hva = addr;
 	u64_to_u8(hva, &eic->kpie[eic->pie_read]);//操作:值
 	eic->pie_read += sizeof(uint64_t);
 	debug_printk("eic_report_addr %lx\n", addr);
 	dump_eic(eic);
 }
 
 static int eic_add_page(struct ept_idle_ctrl *eic,
 			unsigned long addr,
 			unsigned long next,
 			enum ProcIdlePageType page_type)
 {
 	int page_size = pagetype_size[page_type];//获取指定类型的页大小
 
 	debug_printk("eic_add_page addr=%lx next=%lx "
 		     "page_type=%d pagesize=%dK\n",
 		     addr, next, (int)page_type, (int)page_size >> 10);
 	dump_eic(eic);
 
 	/* align kernel/user vision of cursor position */
 	next = round_up(next, page_size);
 
 	if (!eic->pie_read ||
 	    addr + eic->gpa_to_hva != eic->next_hva) {
 		/* merge hole */
 		if (page_type == PTE_HOLE ||
 		    page_type == PMD_HOLE) {
 			set_restart_gpa(next, "PTE_HOLE|PMD_HOLE");
 			return 0;
 		}
 
 		if (addr + eic->gpa_to_hva < eic->next_hva) {
 			debug_printk("ept_idle: addr moves backwards\n");
 			WARN_ONCE(1, "ept_idle: addr moves backwards");
 		}
 
 		if (eic->pie_read + sizeof(uint64_t) + 2 >= eic->pie_read_max) {
 			set_restart_gpa(addr, "EPT_IDLE_KBUF_FULL");
 			return EPT_IDLE_KBUF_FULL;
 		}
 
 		eic_report_addr(eic, round_down(addr, page_size) +
 							eic->gpa_to_hva);
 	} else {
 		if (PIP_TYPE(eic->kpie[eic->pie_read - 1]) == page_type &&
 		    PIP_SIZE(eic->kpie[eic->pie_read - 1]) < 0xF) {
 			set_next_hva(next + eic->gpa_to_hva, "IN-PLACE INC");
 			set_restart_gpa(next, "IN-PLACE INC");
 			eic->kpie[eic->pie_read - 1]++;
 			WARN_ONCE(page_size < next-addr, "next-addr too large");
 			return 0;
 		}
 		if (eic->pie_read >= eic->pie_read_max) {
 			set_restart_gpa(addr, "EPT_IDLE_KBUF_FULL");
 			return EPT_IDLE_KBUF_FULL;
 		}
 	}
 
 	set_next_hva(next + eic->gpa_to_hva, "NEW-ITEM");
 	set_restart_gpa(next, "NEW-ITEM");
 	eic->kpie[eic->pie_read] = PIP_COMPOSE(page_type, 1);
 	eic->pie_read++;
 
 	return 0;
 }
 
 static int ept_pte_range(struct ept_idle_ctrl *eic,
 			 pmd_t *pmd, unsigned long addr, unsigned long end)//Page Table Entry，页面表，最后一级页表，指向物理页面。
 {
 	pte_t *pte;
 	enum ProcIdlePageType page_type;
 	int err = 0;
 
 	pte = pte_offset_kernel(pmd, addr);
 	do {
 		if (!ept_pte_present(*pte))
 			page_type = PTE_HOLE;
 		else if (!test_and_clear_bit(_PAGE_BIT_EPT_ACCESSED,
 					     (unsigned long *) &pte->pte))
 			page_type = PTE_IDLE;
 		else {
 			page_type = PTE_ACCESSED;
 		}
 
 		err = eic_add_page(eic, addr, addr + PAGE_SIZE, page_type);
 		if (err)
 			break;
 	} while (pte++, addr += PAGE_SIZE, addr != end);
 
 	return err;
 }
 
 static int ept_pmd_range(struct ept_idle_ctrl *eic,
 			 pud_t *pud, unsigned long addr, unsigned long end)//Page Middle Derectory，页中间目录，是第三级页表。
 {
 	pmd_t *pmd;
 	unsigned long next;
 	enum ProcIdlePageType page_type;
 	enum ProcIdlePageType pte_page_type;
 	int err = 0;
 
 	if (eic->flags & SCAN_HUGE_PAGE)
 		pte_page_type = PMD_IDLE_PTES;
 	else
 		pte_page_type = IDLE_PAGE_TYPE_MAX;
 
 	pmd = pmd_offset(pud, addr);
 	do {
 		next = pmd_addr_end(addr, end);
 
 		if (!ept_pmd_present(*pmd))
 			page_type = PMD_HOLE;	/* likely won't hit here */
 		else if (!test_and_clear_bit(_PAGE_BIT_EPT_ACCESSED,
 					     (unsigned long *)pmd)) {
 			if (pmd_large(*pmd))
 				page_type = PMD_IDLE;
 			else if (eic->flags & SCAN_SKIM_IDLE)
 				page_type = PMD_IDLE_PTES;
 			else
 				page_type = pte_page_type;
 		} else if (pmd_large(*pmd)) {
 			page_type = PMD_ACCESSED;
 		} else
 			page_type = pte_page_type;
 
 		if (page_type != IDLE_PAGE_TYPE_MAX)
 			err = eic_add_page(eic, addr, next, page_type);
 		else
 			err = ept_pte_range(eic, pmd, addr, next);
 		if (err)
 			break;
 	} while (pmd++, addr = next, addr != end);
 
 	return err;
 }
 
 static int ept_pud_range(struct ept_idle_ctrl *eic,
 			 p4d_t *p4d, unsigned long addr, unsigned long end)//Page Upper Directory，页上级目录，是第二级页表
 {
 	pud_t *pud;
 	unsigned long next;
 	int err = 0;
 
 	pud = pud_offset(p4d, addr);
 	do {
 		next = pud_addr_end(addr, end);
 
 		if (!ept_pud_present(*pud)) {
 			set_restart_gpa(next, "PUD_HOLE");
 			continue;
 		}
 
 		if (pud_large(*pud))
 			err = eic_add_page(eic, addr, next, PUD_PRESENT);
 		else
 			err = ept_pmd_range(eic, pud, addr, next);
 
 		if (err)
 			break;
 	} while (pud++, addr = next, addr != end);
 
 	return err;
 }
 
 static int ept_p4d_range(struct ept_idle_ctrl *eic,
 			 pgd_t *pgd, unsigned long addr, unsigned long end)
 {
 	p4d_t *p4d;
 	unsigned long next;
 	int err = 0;
 
 	p4d = p4d_offset(pgd, addr);
 	do {
 		next = p4d_addr_end(addr, end);
 		if (!ept_p4d_present(*p4d)) {
 			set_restart_gpa(next, "P4D_HOLE");
 			continue;
 		}
 
 		err = ept_pud_range(eic, p4d, addr, next);
 		if (err)
 			break;
 	} while (p4d++, addr = next, addr != end);
 
 	return err;
 }
 
 static int ept_page_range(struct ept_idle_ctrl *eic,
 			  unsigned long addr,
 			  unsigned long end)
 {
 	struct kvm_vcpu *vcpu;
 	struct kvm_mmu *mmu;
 	pgd_t *ept_root;
 	pgd_t *pgd;
 	unsigned long next;
 	int err = 0;
 
 	BUG_ON(addr >= end);
 
 	spin_lock(&eic->kvm->mmu_lock);
 
 	vcpu = kvm_get_vcpu(eic->kvm, 0);
 	if (!vcpu) {
 		err = -EINVAL;
 		goto out_unlock;
 	}
 
 	mmu = vcpu->arch.mmu;//获取ept表项page的hpa
 	if (!VALID_PAGE(mmu->root_hpa)) {
 		err = -EINVAL;
 		goto out_unlock;
 	}

 	ept_root = __va(mmu->root_hpa);//获取ept根页表的物理地址hpa
 
 	local_irq_disable();//屏蔽当前CPU上的所有中断
  /***
    #define pgd_offset_pgd(pgd, address) 
        (pgd + pgd_index((address)))
        pgd_index() is used get the offset into the pgd page's array of pgd_t's;
  ***/
 	pgd = pgd_offset_pgd(ept_root, addr);
 	do {
  /***
    #define pgd_addr_end(addr, end)						\
    ({	
        unsigned long __boundary = ((addr) + PGDIR_SIZE) & PGDIR_MASK;	\
	    (__boundary - 1 < (end) - 1)? __boundary: (end);		\
    })
    计算下一个将要被映射的虚拟地址，如果addr到end可以被一个pgd映射的话，那么返回end的值
    //PGDIR_SIZE 就是页目录表中一个表项 (pgd_t) 对应的虚拟地址空间
    //#define PGDIR_MASK (~(PGDIR_SIZE - 1))
  ***/
 		next = pgd_addr_end(addr, end);
 		if (!ept_pgd_present(*pgd)) {//no entry in EPT PGD?
 			set_restart_gpa(next, "PGD_HOLE");
 			continue;
 		}
 
 		err = ept_p4d_range(eic, pgd, addr, next);
 		if (err)
 			break;
 	} while (pgd++, addr = next, addr != end);//遍历pgd所有表项
 	local_irq_enable();//结束中断屏蔽
 out_unlock:
 	spin_unlock(&eic->kvm->mmu_lock);
 	return err;
 }
 
 static void init_ept_idle_ctrl_buffer(struct ept_idle_ctrl *eic)
 {
 	eic->pie_read = 0;
 	eic->pie_read_max = min(EPT_IDLE_KBUF_SIZE,
 				eic->buf_size - eic->bytes_copied);
 	/* reserve space for PIP_CMD_SET_HVA in the end */
 	eic->pie_read_max -= sizeof(uint64_t) + 1;
 	memset(eic->kpie, 0, sizeof(eic->kpie));
 }
 
 static int ept_idle_copy_user(struct ept_idle_ctrl *eic,
 			      unsigned long start, unsigned long end)
 {
 	int bytes_read;
 	int lc = 0;	/* last copy? */
 	int ret;
 
 	debug_printk("ept_idle_copy_user %lx %lx\n", start, end);
 	dump_eic(eic);
 
 	/* Break out of loop on no more progress. */
 	if (!eic->pie_read) {
 		lc = 1;
 		if (start < end)
 			start = end;
 	}
 
 	if (start >= end && start > eic->next_hva) {
 		set_next_hva(start, "TAIL-HOLE");
 		eic_report_addr(eic, start);
 	}
 
 	bytes_read = eic->pie_read;
 	if (!bytes_read)
 		return 1;
 
 	ret = copy_to_user(eic->buf, eic->kpie, bytes_read);
 	if (ret)
 		return -EFAULT;
 
 	eic->buf += bytes_read;
 	eic->bytes_copied += bytes_read;
 	if (eic->bytes_copied >= eic->buf_size)
 		return EPT_IDLE_BUF_FULL;
 	if (lc)
 		return lc;
 
 	init_ept_idle_ctrl_buffer(eic);
 	cond_resched();
 	return 0;
 }
 
 /*
  * Depending on whether hva falls in a memslot:
  *
  * 1) found => return gpa and remaining memslot size in *addr_range
  *
  *                 |<----- addr_range --------->|
  *         [               mem slot             ]
  *                 ^hva
  *
  * 2) not found => return hole size in *addr_range
  *
  *                 |<----- addr_range --------->|
  *                                              [   first mem slot above hva  ]
  *                 ^hva
  *
  * If hva is above all mem slots, *addr_range will be ~0UL. We can finish read(2).
  */
 static unsigned long ept_idle_find_gpa(struct ept_idle_ctrl *eic,
 				       unsigned long hva,
 				       unsigned long *addr_range)//物理机虚拟地址到客户机物理地址的转换
 {
 	struct kvm *kvm = eic->kvm;
 	struct kvm_memslots *slots;
 	struct kvm_memory_slot *memslot;
 	unsigned long hva_end;
 	gfn_t gfn;
 
 	*addr_range = ~0UL;
 	mutex_lock(&kvm->slots_lock);
 	slots = kvm_memslots(eic->kvm);
 	kvm_for_each_memslot(memslot, slots) {
 		hva_end = memslot->userspace_addr +
 		    (memslot->npages << PAGE_SHIFT);//虚拟空间地址的末地址
 
 		if (hva >= memslot->userspace_addr && hva < hva_end) {//若hva落在指定的某个memslot范围内
 			gpa_t gpa;
 			gfn = hva_to_gfn_memslot(hva, memslot);//宿主机虚拟地址到客户机物理页框的转换
 			*addr_range = hva_end - hva;//可访问的地址空间大小
 			gpa = gfn_to_gpa(gfn);//客户机物理页框到客户机物理地址的转换
 			debug_printk("ept_idle_find_gpa slot %lx=>%llx %lx=>%llx "
 				     "delta %llx size %lx\n",
 				     memslot->userspace_addr,
 				     gfn_to_gpa(memslot->base_gfn),
 				     hva, gpa,
 				     hva - gpa,
 				     memslot->npages << PAGE_SHIFT);
 			mutex_unlock(&kvm->slots_lock);
 			return gpa;
 		}
 
 		if (memslot->userspace_addr > hva)
 			*addr_range = min(*addr_range,
 					  memslot->userspace_addr - hva);
 	}
 	mutex_unlock(&kvm->slots_lock);
 	return INVALID_PAGE;
 }
 
 static int ept_idle_supports_cpu(struct kvm *kvm)//判断是否支持EPT tracking
 {
 	struct kvm_vcpu *vcpu;
 	struct kvm_mmu *mmu;
 	int ret;
 
 	vcpu = kvm_get_vcpu(kvm, 0);
 	if (!vcpu)
 		return -EINVAL;
 
 	spin_lock(&kvm->mmu_lock);
 	mmu = vcpu->arch.mmu;
 	if (mmu->mmu_role.base.ad_disabled) {//禁止进行EPT的tracking
 		printk(KERN_NOTICE
 		       "CPU does not support EPT A/D bits tracking\n");
 		ret = -EINVAL;
 	} else if (mmu->shadow_root_level != 4 + (! !pgtable_l5_enabled())) {
 		printk(KERN_NOTICE "Unsupported EPT level %d\n",
 		       mmu->shadow_root_level);
 		ret = -EINVAL;
 	} else
 		ret = 0;
 	spin_unlock(&kvm->mmu_lock);
 
 	return ret;
 }
 
 static int ept_idle_walk_hva_range(struct ept_idle_ctrl *eic,
 				   unsigned long start, unsigned long end)//扫描从start开始到end结束的hva
 {
 	unsigned long gpa_addr;
 	unsigned long addr_range;
 	int ret;
  
 	ret = ept_idle_supports_cpu(eic->kvm);//判断是否支持ept扫描
 	if (ret)
 		return ret;
 
 	init_ept_idle_ctrl_buffer(eic);//初始化eic内涵的数组kpie初始化eic内涵的数组kpie 等
 
 	for (; start < end;) {
 		gpa_addr = ept_idle_find_gpa(eic, start, &addr_range);//通过start的hva，借助对应memslot，得到gpa_addr和当前memslot留下的地址长度addr_range
  
 		if (gpa_addr == INVALID_PAGE) {
 			eic->gpa_to_hva = 0;
 			if (addr_range == ~0UL) /* beyond max virtual address */
 				set_restart_gpa(TASK_SIZE, "EOF");
 			else {
 				start += addr_range;
 				set_restart_gpa(start, "OUT-OF-SLOT");//赋值eic中的restart_gpa
 			}
 		} else {
 			eic->gpa_to_hva = start - gpa_addr;//gpa->hva的线性映射关系(斜率为1，表现为截距的差值)
 			ept_page_range(eic, gpa_addr, gpa_addr + addr_range);
 		}
 
 		start = eic->restart_gpa + eic->gpa_to_hva;
 		ret = ept_idle_copy_user(eic, start, end);
 		if (ret)
 			break;
 	}
 
 	if (eic->bytes_copied)
 		ret = 0;
 	return ret;
 }
 
 static ssize_t ept_idle_read(struct file *file, char *buf,
 			     size_t count, loff_t *ppos)//该函数传入文件描述符，用户buffer，读取长度，文件偏移
 {
     /***
     ssize_t dev_read(struct file *filp,char __user *buf,size_t count ,loff_t *ppos);
    最后一个参量会在数据传输后更新，反映在系统调用后当前的文件位置。
    内核在适当情况下会将文件位置的改变传回到file生成的filp结构中。

    struct file代表一个打开的文件描述符，它不是专门给驱动程序使用的，系统中每一个打开的文件在内核中都有一个关联的 struct file。
    它由内核在open时创建，并传递给在文件上操作的任何函数，知道最后关闭。
    当文件的所有实例都关闭之后，内核释放这个数据结构。
    private_data其实是用来保存自定义设备结构体的地址的。
    自定义结构体的地址被保存在private_data后，可以在read、write等驱动函数中被传递和调用自定义设备结构体中的成员。
     ***/
 	struct mm_struct *mm = file->private_data;
     /***
        struct ept_idle_ctrl {
            struct mm_struct *mm;
            struct kvm *kvm;

            uint8_t kpie[EPT_IDLE_KBUF_SIZE];
            int pie_read;
            int pie_read_max;

            void __user *buf;
            int buf_size;
            int bytes_copied;

            unsigned long next_hva;
            unsigned long gpa_to_hva;
            unsigned long restart_gpa;
            unsigned long last_va;

            unsigned int flags;
        };
     ***/
 	struct ept_idle_ctrl *eic;
 	unsigned long hva_start = *ppos;//通过偏移指定hva
    /*** 
    由这里的计算方式可以得知，count应该指page的数量，左移PAGE_SHIFT得到字节(byte)数量，再左移3得到bit数量
    ***/
 	unsigned long hva_end = hva_start + (count << (3 + PAGE_SHIFT));//通过count配个偏移确定hva_end
 	int ret;
    /***
    从用户角度看，Linux进程的虚地址是线性的，它分为两部分：内核空间和用户空间。
    用户空间占据地址的低部分，从0到TASK_SIZE（TASK_SIZE的值是与具体的硬件平台相关的，在include/asm/processor.h中定义），剩余部分为内核空间。 
    ***/
 	if (hva_start >= TASK_SIZE) {
 		debug_printk("ept_idle_read past TASK_SIZE: %lx %lx\n",
 			     hva_start, TASK_SIZE);
 		return 0;
 	}
 
 	if (!mm_kvm(mm))//返回mm结构体中保存的kvm，若返回为null，调用proc_mm_idle_operations的read操作
 		return mm_idle_read(file, buf, count, ppos);
 
 	if (hva_end <= hva_start) {//起始地址大于结束地址
 		debug_printk("ept_idle_read past EOF: %lx %lx\n",
 			     hva_start, hva_end);
 		return 0;
 	}
 	if (*ppos & (PAGE_SIZE - 1)) {//未进行对齐
 		debug_printk("ept_idle_read unaligned ppos: %lx\n",
 			     hva_start);
 		return -EINVAL;
 	}
 	if (count < EPT_IDLE_BUF_MIN) {//read数据量过小
 		debug_printk("ept_idle_read small count: %lx\n",
 			     (unsigned long)count);
 		return -EINVAL;
 	}
 
 	eic = kzalloc(sizeof(*eic), GFP_KERNEL);//在内核空间分配eic，页空间不会被换出
 	if (!eic)
 		return -ENOMEM;
    /***
    mmget() - Pin the address space associated with a &struct mm_struct.
    @mm: The address space to pin.
    atomic_inc_not_zero - increment if not zero
    @v: pointer of type atomic_t:mm->mm_users
    ***/
 	if (!mm || !mmget_not_zero(mm)) {
 		ret = -ESRCH;
 		goto out_free_eic;
 	}
 
 	eic->buf = buf;
 	eic->buf_size = count;
 	eic->mm = mm;
 	eic->kvm = mm_kvm(mm);
 	if (!eic->kvm) {
 		ret = -EINVAL;
 		goto out_mm;
 	}
 
 	kvm_get_kvm(eic->kvm);//增加用户引用计数:kvm->user_count
 
 	ret = ept_idle_walk_hva_range(eic, hva_start, hva_end);
 	if (ret)
 		goto out_kvm;
 
 	ret = eic->bytes_copied;
 	*ppos = eic->next_hva;
 	debug_printk("ppos=%lx bytes_copied=%d\n",
 		     eic->next_hva, ret);
 out_kvm:
 	kvm_put_kvm(eic->kvm);//减少用户引用计数:kvm->user_count
 out_mm:
 	mmput(mm);//参考mmget
 out_free_eic:
 	kfree(eic);//释放eic空间
 	return ret;
 }
 
 static int ept_idle_open(struct inode *inode, struct file *file)
 {
 	if (!try_module_get(THIS_MODULE))//判断module是否已经加载并处于工作状态
 		return -EBUSY;
 
 	return 0;
 }
 
 static int ept_idle_release(struct inode *inode, struct file *file)
 {
 	struct mm_struct *mm = file->private_data;
 	struct kvm *kvm;
 	int ret = 0;
 
 	if (!mm) {
 		ret = -EBADF;
 		goto out;
 	}
 
 	kvm = mm_kvm(mm);
 	if (!kvm) {
 		ret = -EINVAL;
 		goto out;
 	}
 
 	spin_lock(&kvm->mmu_lock);
 	kvm_flush_remote_tlbs(kvm); //影子页表无操作,主要针对硬件ept页表进行刷新
 	spin_unlock(&kvm->mmu_lock);
 
 out:
 	module_put(THIS_MODULE);//释放引用计数
 	return ret;
 }
 
 extern struct file_operations proc_ept_idle_operations;
 
 static int ept_idle_entry(void)//模块初始化，定义file_operations中对应的3种操作
 {
 	proc_ept_idle_operations.owner = THIS_MODULE;
 	proc_ept_idle_operations.read = ept_idle_read;
 	proc_ept_idle_operations.open = ept_idle_open;
 	proc_ept_idle_operations.release = ept_idle_release;
 
 	return 0;
 }
 
 static void ept_idle_exit(void)//模块退出操作，将file_operations中定义的操作全部清空
 {
 	memset(&proc_ept_idle_operations, 0, sizeof(proc_ept_idle_operations));
 }
 
 MODULE_LICENSE("GPL");
 module_init(ept_idle_entry);
 module_exit(ept_idle_exit);
