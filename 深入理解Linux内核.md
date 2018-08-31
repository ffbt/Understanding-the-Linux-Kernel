# 深入理解 Linux 内核

## 第一章 绪论

### 1.1 Linux 与其他类 Unix 内核的比较

### 1.2 硬件的依赖性

### 1.3 Linux 版本

### 1.4 操作系统基本概念

### 1.5 Unix 文件系统概述

### 1.6 Unix 内核概述

## 第二章 内存寻址

### 2.1 内存地址

### 2.2 硬件中的分段

### 2.3 Linux 中的分段

### 2.4 硬件中的分页

### 2.5 Linux 中的分页

## 第三章 进程

### 3.1 进程、轻量级进程和线程

### 3.2 进程描述符

### 3.3 进程切换

### 3.4 创建进程

### 3.5 撤销进程

## 第四章 中断和异常

### 4.1 中断信号的作用

### 4.2 中断和异常

### 4.3 中断和异常处理程序的嵌套执行

### 4.4 初始化中断描述符表

### 4.5 异常处理

### 4.6 中断处理

### 4.7 软中断及 tasklet

### 4.8 工作队列

### 4.9 从中断和异常返回

## 第五章 内核同步

### 5.1 内核如何为不同的请求提供服务

### 5.2 同步原语

#### 5.2.4 自旋锁

- 当**内核控制路径**必须访问共享数据结构或进入临界区时，就需要为自己获取一把锁
- 用来在多处理器环境中工作
- 在单处理器系统上，自旋锁仅仅是禁止或启用内核抢占
- 忙等（尝试获取自旋锁的另一个进程不断尝试获取被占用的自旋锁，中间只 pause 一下 ），等待进程可以被抢占
- 临界区禁止内核抢占
- 保护模式下禁止内核抢占的方法：
  1. 执行终端服务例程时
  2. 执行软中断和 `tasklet` 时 
  3. 设置本地 CPU 计数器 `preempt_count `

##### 5.2.4.1 具有内核抢占的 `spin_lock` 宏

- 在抢占式内核的 `spin_lock` 宏中，第一次关抢占，目的是防止死锁（防止一个已经获取自旋锁而未释放的进程被抢占！！）。而后又开抢占，目的是让已经释放自旋锁的进程可以被调度出去，让其他进程可以进入临界区。当然，开启内核抢占后，调度器调度的进程是不是在忙等的进程不可而知！   

1. 禁用内核抢占
2. 是否可以获得自旋锁
3. 不能获得自旋锁，开启内核抢占，给其他进程机会
4. 等待自旋锁空闲
5. 跳到 1

##### 5.2.4.2 非抢占式内核中的 `spin_lock` 宏

- 循环直到获取到锁

##### 5.2.4.3 `spin_unlock` 宏

- `movb $1, slp->slock`
- 启用内核抢占

#### 5.2.5 读 / 写自旋锁

1. 特点
   - 增加内核的并发能力
   - 允许同时读
   - 获取写锁写

2. 读 / 写自旋锁：`rwlock_t` 结构体

```c
typedef struct {
	volatile unsigned int lock;
#ifdef CONFIG_DEBUG_SPINLOCK
	unsigned magic;
#endif
#ifdef CONFIG_PREEMPT
	unsigned int break_lock;	// 是否有其他进程等待该锁
#endif
} rwlock_t;
```

3. `lock` 字段
   - 0 - 23 位：补码，并发进行读操作的内核控制路径的数目
   - 24 位：没有读或写为 1
   - 未锁：0x01000000
   - 获取写锁：0x00000000
   - 多个读锁：0x00ffffff(-1)、0xfffffe(-2)

##### 5.2.5.1 为读获取和释放一个锁

`read_lock` 宏

- 内核抢占：执行与 `spin_lock` 非常相似的操作
- 禁止内核抢占：忙等待自旋锁的释放

##### 5.2.5.2 为写获取和释放一个锁

`write_lock` 宏，与上面类似

#### 5.2.6 顺序锁

`seqlock_t` 结构体

```c
typedef struct {
	unsigned sequence;	// 顺序计数器
	spinlock_t lock;
} seqlock_t;
```

- 读 / 写自旋锁读者和写者优先权相同
- 顺序锁为写者赋予较高的优先级
- 写者永远不会等待（读者正在读时允许写者运行）
- 读者需要重复多次读，两次 `sequence` 相同数据有效

#### 5.2.7 读 - 拷贝 - 更新 (RCU)

- 保护被多个 CPU 读的数据结构
- 允许多个读者和写者并发执行
- 不使用锁，开销小
- 只保护**动态分配，指针引用**的数据结构
- 内核控制路径**不能睡眠**

```c
void fastcall call_rcu(struct rcu_head *head,
				void (*func)(struct rcu_head *rcu))
{
	unsigned long flags;
	struct rcu_data *rdp;

	head->func = func;
	head->next = NULL;
	local_irq_save(flags);
	rdp = &__get_cpu_var(rcu_data);
	*rdp->nxttail = head;
	rdp->nxttail = &head->next;
	local_irq_restore(flags);
}
```

### 5.3 对内核数据结构的同步访问

### 5.4 避免竞争条件的实例

## 第六章 定时测量

### 6.1 时钟和定时器电路

### 6.2 Linux 计时体系结构

### 6.3 更新时间和日期

### 6.4 更新系统统计数

### 6.5 软定时器和延迟函数

### 6.6 与定时测量相关的系统调用

## 第七章 进程调度

### 7.1 调度策略

### 7.2 调度算法

### 7.3 调度程序所使用的数据结构

### 7.4 调度程序所使用的函数

### 7.5 多处理器系统中运行队列的平衡

### 7.6 与调度相关的系统调用

## 第八章 内存管理

### 8.1 页框管理

#### 8.1.4 保留的页框池

- 原子内存请求不能被阻塞
- 为了减小原子内存分配失败发生的可能性，内核保留一个页框池，只有在内存不足时才使用
- 保留内存的数量 -> `min_free_kbytes` -> 1024KB
- 管理区描述符中的字段`pages_min` 管理区内保留页框的数目
- `pages_low` = `pages_min` * 5/4
- `pages_high` = `pages_min` * 3/2

### 8.2 内存区管理

slab 相关数据结构图解

![20131015104307421](./img/20131015104307421.gif)

#### 8.2.3 slab 描述符

#### 8.2.4 普通和专用高速缓存

#### 8.2.5 slab 分配器与分区页框分配器的接口

#### 8.2.6 给高速缓存分配 slab

必须满足两个条件：

- 已发出一个分配新对象的请求
- 高速缓存不包含任何空闲对象

```c
static int cache_grow (kmem_cache_t * cachep, int flags, int nodeid)
{
	struct slab	*slabp;
	void		*objp;
	size_t		 offset;
	int		 local_flags;
	unsigned long	 ctor_flags;

    // ...
    
	// 1. 获取一组页框存放 slab，返回线性地址，见 8.2.5
	/* Get mem for the objs. */
	if (!(objp = kmem_getpages(cachep, flags, nodeid)))
		goto failed;

    // 2. 获得一个新的 slab 描述符，见下一个函数
	/* Get slab management. */
    // offset 见 8.2.10
	if (!(slabp = alloc_slabmgmt(cachep, objp, offset, local_flags)))
		goto opps1;

    // 3. 给定一个页框，可以迅速得到相应高速缓存和 slab 描述符的地址
	set_slab_attr(cachep, slabp, objp);

    // 4. 将构造方法(如果定义了的话)应用到新 slab 包含的所有对象上
	cache_init_objs(cachep, slabp, ctor_flags);

	if (local_flags & __GFP_WAIT)
		local_irq_disable();
	check_irq_off();
	spin_lock(&cachep->spinlock);

	/* Make slab active. */
    // 5. 插入到高速缓存描述符全空 slab 链表的末端
	list_add_tail(&slabp->list, &(list3_data(cachep)->slabs_free));
	STATS_INC_GROWN(cachep);
    // 6. 更新高速缓存中空闲对象计数器
	list3_data(cachep)->free_objects += cachep->num;
	spin_unlock(&cachep->spinlock);
	return 1;
opps1:
	kmem_freepages(cachep, objp);
failed:
	if (local_flags & __GFP_WAIT)
		local_irq_disable();
	return 0;
}
```

```c
static struct slab* alloc_slabmgmt (kmem_cache_t *cachep,
			void *objp, int colour_off, int local_flags)
{
	struct slab *slabp;
	
    // #define	OFF_SLAB(x)	((x)->flags & CFLGS_OFF_SLAB)
	if (OFF_SLAB(cachep)) {	// slab 描述符存放在 slab 外部
		/* Slab management obj is off-slab. */
        // 见 8.2.12
        // 每一个对象为一个 slab 描述符
		slabp = kmem_cache_alloc(cachep->slabp_cache, local_flags);
		if (!slabp)
			return NULL;
	} else {	// 从 slab 的第一个页框中分配 slab 描述符
		slabp = objp+colour_off;
		colour_off += cachep->slab_size;
	}
	slabp->inuse = 0;
	slabp->colouroff = colour_off;
	slabp->s_mem = objp+colour_off;

	return slabp;
}
```

```c
static void set_slab_attr(kmem_cache_t *cachep, struct slab *slabp, void *objp)
{
	int i;
	struct page *page;

	/* Nasty!!!!!! I hope this is OK. */
	i = 1 << cachep->gfporder;
	page = virt_to_page(objp);
	do {
        // 强制转换
        // #define	SET_PAGE_CACHE(pg,x)  ((pg)->lru.next = (struct list_head *)(x))
		SET_PAGE_CACHE(page, cachep);
        // #define	SET_PAGE_SLAB(pg,x)   ((pg)->lru.prev = (struct list_head *)(x))
		SET_PAGE_SLAB(page, slabp);
		page++;
	} while (--i);
}
```

#### 8.2.7 从高速缓存中释放 slab

必须满足两个条件：

- slab 高速缓存中有太多的空闲对象
- 被周期性调用的定时器函数确定是否**有完全未使用的** slab 能被释放

#### 8.2.8 对象描述符

`kmem_bufctl_t` 结构体 (`unsigned short`)

- 位于相应的 slab 描述符之后
- 值为下一个空闲对象在 slab 中的下标，形成一个空闲对象链表

#### 8.2.9 对齐内存中的对象

```c
kmem_cache_t *
kmem_cache_create (const char *name, size_t size, size_t align,
	unsigned long flags, void (*ctor)(void*, kmem_cache_t *, unsigned long),
	void (*dtor)(void*, kmem_cache_t *, unsigned long))
{
    size_t left_over, slab_size, ralign;
	kmem_cache_t *cachep = NULL;
    
	// ...

	/* calculate out the final buffer alignment: */
	/* 1) arch recommendation: can be overridden for debug */
	if (flags & SLAB_HWCACHE_ALIGN) {	// 0
		/* Default alignment: as specified by the arch code.
		 * Except if an object is really small, then squeeze multiple
		 * objects into one cacheline.
		 */
		ralign = cache_line_size();	// L1_CACHE_BYTES 高速缓存行(cache line)
		while (size <= ralign/2)	// 2
			ralign /= 2;
	} else {	// 缺省情况
		ralign = BYTES_PER_WORD;
	}
    
    // ...
}
```

#### 8.2.10 Slab 着色

- 把 slab 中的一些空闲区域从末尾移到开始，达到把对象展开在不同的线性地址的效果。
- 对齐：对象的地址为 `aln` 的倍数

```c
static int cache_grow (kmem_cache_t * cachep, int flags, int nodeid)
{
	// ...

	/* Get colour for the slab, and cal the next value. */
	offset = cachep->colour_next;	// col
	cachep->colour_next++;
	if (cachep->colour_next >= cachep->colour)
		cachep->colour_next = 0;
    // dsize == 0 猜测：slab对象描述符在外部
	offset *= cachep->colour_off;	// colour_off: aln

	// ...

	/* Get slab management. */
	if (!(slabp = alloc_slabmgmt(cachep, objp, offset, local_flags)))
		goto opps1;

	// ...
}
```

#### 8.2.11 空闲 Slab 对象的本地高速缓存

slab 本地高速缓存：`array_cache` 结构体

- 每 CPU 元素
- 本地高速缓存数组紧跟其之后
- avail 存放 slab 中对象数组的下标

#### 8.2.12 分配 Slab 对象

1. 从 avail 中找
2. 从共享本地高速缓存填充 avail
3. 从部分或空闲 slab 中的一个空闲对象填充 avail
4. 换一个对象再找

```c
static void* cache_alloc_refill(kmem_cache_t* cachep, int flags)
{
	int batchcount;
	struct kmem_list3 *l3;
	struct array_cache *ac;

	check_irq_off();
	ac = ac_data(cachep);	// 1
retry:
	batchcount = ac->batchcount;
	if (!ac->touched && batchcount > BATCHREFILL_LIMIT) {
		/* if there was little recent activity on this
		 * cache, then perform only a partial refill.
		 * Otherwise we could generate refill bouncing.
		 */
		batchcount = BATCHREFILL_LIMIT;
	}
	l3 = list3_data(cachep);

	BUG_ON(ac->avail > 0);
	spin_lock(&cachep->spinlock);	// 2
	if (l3->shared) {	// 3.1
		struct array_cache *shared_array = l3->shared;
		if (shared_array->avail) {	// 3.2
			if (batchcount > shared_array->avail)
				batchcount = shared_array->avail;
            
            /* 
             * ac->avail == 0
             * 把 shared_array->avail 中 batchcount 个可使用对象的指针给了 ac->avail
             */
			shared_array->avail -= batchcount;	// 3.3
			ac->avail = batchcount;
            
             /*
             static inline void ** ac_entry(struct array_cache *ac)
			{
				// 返回 ac 后的本地高速缓存数组
				return (void**)(ac+1);
			}
              */ 
			memcpy(ac_entry(ac), &ac_entry(shared_array)[shared_array->avail],
					sizeof(void*)*batchcount);	// 3.4
			shared_array->touched = 1;
			goto alloc_done;	// -> 6
		}
	}
	while (batchcount > 0) {	// 4.a.1
		struct list_head *entry;
		struct slab *slabp;
		/* Get slab alloc is to come from. */
		entry = l3->slabs_partial.next;
		if (entry == &l3->slabs_partial) {	// slabs_partial 为空
			l3->free_touched = 1;	// 由 slab 分配器的页回收算法使用
			entry = l3->slabs_free.next;
			if (entry == &l3->slabs_free)	// slabs_free 为空
				goto must_grow;	// -> 5
		}

         // 4.a.2
		slabp = list_entry(entry, struct slab, list);
		check_slabp(cachep, slabp);
		check_spinlock_acquired(cachep);
		while (slabp->inuse < cachep->num && batchcount--) {
			kmem_bufctl_t next;
			STATS_INC_ALLOCED(cachep);
			STATS_INC_ACTIVE(cachep);
			STATS_SET_HIGH(cachep);

             // 4.b
			/* get obj pointer */
			ac_entry(ac)[ac->avail++] = slabp->s_mem + slabp->free*cachep->objsize;

			slabp->inuse++;
             /*
             static inline kmem_bufctl_t *slab_bufctl(struct slab *slabp)
             {
             	 // 返回 slab 描述符后的对象描述符数组
                 return (kmem_bufctl_t *)(slabp+1);
             }
              */
			next = slab_bufctl(slabp)[slabp->free];
#if DEBUG
			slab_bufctl(slabp)[slabp->free] = BUFCTL_FREE;
#endif
		       	slabp->free = next;
		}
		check_slabp(cachep, slabp);

         // 4.c
		/* move slabp to correct slabp list: */
		list_del(&slabp->list);
		if (slabp->free == BUFCTL_END)
			list_add(&slabp->list, &l3->slabs_full);
		else
			list_add(&slabp->list, &l3->slabs_partial);
	}

must_grow:
	l3->free_objects -= ac->avail;	// 5
alloc_done:
	spin_unlock(&cachep->spinlock);	// 6

	if (unlikely(!ac->avail)) {	// 7.1
		int x;
		x = cache_grow(cachep, flags, -1);	// 8
		
         // 9
		// cache_grow can reenable interrupts, then ac could change.
		ac = ac_data(cachep);
		if (!x && ac->avail == 0)	// no objects in sight? abort
			return NULL;

		if (!ac->avail)		// objects refilled by interrupt?
			goto retry;
	}
	ac->touched = 1;	// 7.2
	return ac_entry(ac)[--ac->avail];	// 7.3
}
```

#### 8.2.13 释放 Slab 对象

```c
static void cache_flusharray (kmem_cache_t* cachep, struct array_cache *ac)
{
	int batchcount;

	batchcount = ac->batchcount;
#if DEBUG
	BUG_ON(!batchcount || batchcount > ac->avail);
#endif
	check_irq_off();
	spin_lock(&cachep->spinlock);	// 1
	if (cachep->lists.shared) {	// 2.1
		struct array_cache *shared_array = cachep->lists.shared;
		int max = shared_array->limit-shared_array->avail;
		if (max) {	// 2.2
			if (batchcount > max)
				batchcount = max;
			memcpy(&ac_entry(shared_array)[shared_array->avail],
					&ac_entry(ac)[0],
					sizeof(void*)*batchcount);	// 2.3
			shared_array->avail += batchcount;
			goto free_done;	// -> 4
		}
	}

	free_block(cachep, &ac_entry(ac)[0], batchcount);	// 3
free_done:
#if STATS
	{
		int i = 0;
		struct list_head *p;

		p = list3_data(cachep)->slabs_free.next;
		while (p != &(list3_data(cachep)->slabs_free)) {
			struct slab *slabp;

			slabp = list_entry(p, struct slab, list);
			BUG_ON(slabp->inuse);

			i++;
			p = p->next;
		}
		STATS_SET_FREEABLE(cachep, i);
	}
#endif
	spin_unlock(&cachep->spinlock);	// 4
	ac->avail -= batchcount;	// 5
	memmove(&ac_entry(ac)[0], &ac_entry(ac)[batchcount],
			sizeof(void*)*ac->avail);	// 6	为什么不把高地址的复制过去？？
}
```

```c
static void free_block(kmem_cache_t *cachep, void **objpp, int nr_objects)
{
	int i;

	check_spinlock_acquired(cachep);

	/* NUMA: move add into loop */
	cachep->lists.free_objects += nr_objects;	// a

	for (i = 0; i < nr_objects; i++) {
		void *objp = objpp[i];
		struct slab *slabp;
		unsigned int objnr;

         // #define	GET_PAGE_SLAB(pg)     ((struct slab *)(pg)->lru.prev)
		slabp = GET_PAGE_SLAB(virt_to_page(objp));	// b
		list_del(&slabp->list);	// c
		objnr = (objp - slabp->s_mem) / cachep->objsize;	// d
		check_slabp(cachep, slabp);
#if DEBUG
		if (slab_bufctl(slabp)[objnr] != BUFCTL_FREE) {
			printk(KERN_ERR "slab: double free detected in cache '%s', objp %p.\n",
						cachep->name, objp);
			BUG();
		}
#endif
		slab_bufctl(slabp)[objnr] = slabp->free;	// e
		slabp->free = objnr;	// e
		STATS_DEC_ACTIVE(cachep);
		slabp->inuse--;	// f
		check_slabp(cachep, slabp);

		/* fixup slab chains */
		if (slabp->inuse == 0) {	// g.1
			if (cachep->lists.free_objects > cachep->free_limit) {	// g.2
				cachep->lists.free_objects -= cachep->num;	// g.3
				slab_destroy(cachep, slabp);	// g.3	见 8.2.7
			} else {	// h
				list_add(&slabp->list,
				&list3_data_ptr(cachep, objp)->slabs_free);
			}
		} else {	// i
			/* Unconditionally move a slab to the end of the
			 * partial list on free - maximum time for the
			 * other objects to be freed, too.
			 */
			list_add_tail(&slabp->list,
				&list3_data_ptr(cachep, objp)->slabs_partial);
		}
	}
}
```

#### 8.2.14 通用对象

`kmalloc` 和 `kfree` 分别用于分配和释放物理地址

#### 8.2.15 内存池

- 一个内存池允许一个内核成分，如块设备子系统，仅在内存不足的紧急情况下分配一些动态内存来使用。
- 与 8.1.4 区分

### 8.3 非连续内存区管理

## 第九章 进程地址空间

### 9.1 进程的地址空间

### 9.2 内存描述符

### 9.3 线性区

### 9.4 缺页异常处理程序

### 9.5 创建和删除进程的地址空间

### 9.6 堆的管理

## 第十章 系统调用

### 10.1 POSIX API 和系统调用

### 10.2 系统调用处理程序及服务例程

### 10.3 进入和退出系统调用

### 10.4 参数传递

### 10.5 内核封装例程

## 宏定义索引

### 第八章

#### __GFP

- P305
- 用于请求页框的标志

#### GFP

- P305
- 用于请求页框的一组标志