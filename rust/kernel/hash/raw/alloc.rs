pub(crate) use self::inner::{do_alloc, Allocator, Global};

// Kernel case.
// This uses the kernel allocator and flags specified.
mod inner {
    use core::{alloc::Layout, ptr::NonNull};

    use kernel::prelude::*;

    pub(crate) use crate::alloc::{allocator::Kmalloc as Global, AllocError, Allocator};

    pub(crate) fn do_alloc<A: Allocator>(layout: Layout) -> Result<NonNull<u8>, AllocError> {
        A::alloc(layout, GFP_KERNEL).map(|ptr| ptr.cast())
    }
}
