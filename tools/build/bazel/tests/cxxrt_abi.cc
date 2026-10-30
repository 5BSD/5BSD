// SPDX-License-Identifier: BSD-2-Clause
// Exercise compiler-generated ABI calls without depending on libc++ headers.
struct Base { virtual ~Base() {} };
struct Derived : Base { int value = 42; };
struct Other : Base {};

struct Lifetime {
    int *live;
    explicit Lifetime(int *count) : live(count) { ++*live; }
    Lifetime(const Lifetime &other) : live(other.live) { ++*live; }
    ~Lifetime() { --*live; }
};

static int initialized;
static int &once()
{
    static int value = ++initialized;
    return value;
}

int main()
{
    Derived object;
    // Keep the dynamic type opaque to constant folding at the cast sites.
    Base *volatile pointer = &object;
    Base *base = pointer;
    Derived *derived = dynamic_cast<Derived *>(base);
    if (derived != &object || derived->value != 42 ||
        dynamic_cast<Other *>(base) != nullptr)
        return 1;
    int live = 0;
    try {
        Lifetime local(&live);
        throw local;
    } catch (const Lifetime &caught) {
        if (caught.live != &live || live != 1)
            return 2;
    } catch (...) {
        return 3;
    }
    if (live != 0)
        return 4;
    try {
        throw 73;
    } catch (int value) {
        if (value != 73)
            return 5;
    }
    if (once() != 1 || once() != 1 || initialized != 1)
        return 6;
    return 0;
}
