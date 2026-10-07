/** Binary min-heap keyed by a numeric priority. */
export class MinHeap<T> {
  private readonly items: Array<{ priority: number; seq: number; value: T }> = [];
  private seq = 0;

  get size(): number {
    return this.items.length;
  }

  push(value: T, priority: number): void {
    // seq makes ordering stable (FIFO among equal priorities) → deterministic results
    this.items.push({ priority, seq: this.seq++, value });
    this.up(this.items.length - 1);
  }

  pop(): T | undefined {
    const top = this.items[0];
    if (!top) return undefined;
    const last = this.items.pop()!;
    if (this.items.length > 0) {
      this.items[0] = last;
      this.down(0);
    }
    return top.value;
  }

  private less(a: number, b: number): boolean {
    const x = this.items[a]!;
    const y = this.items[b]!;
    return x.priority < y.priority || (x.priority === y.priority && x.seq < y.seq);
  }

  private swap(a: number, b: number): void {
    const t = this.items[a]!;
    this.items[a] = this.items[b]!;
    this.items[b] = t;
  }

  private up(i: number): void {
    while (i > 0) {
      const parent = (i - 1) >> 1;
      if (!this.less(i, parent)) break;
      this.swap(i, parent);
      i = parent;
    }
  }

  private down(i: number): void {
    const n = this.items.length;
    for (;;) {
      const l = 2 * i + 1;
      const r = l + 1;
      let m = i;
      if (l < n && this.less(l, m)) m = l;
      if (r < n && this.less(r, m)) m = r;
      if (m === i) break;
      this.swap(i, m);
      i = m;
    }
  }
}
