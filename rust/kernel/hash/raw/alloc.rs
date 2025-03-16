pub(crate) use self::inner::{do_alloc, Allocator, Global};

// Kernel case.
// This uses the kernel allocator and flags specified.
mod inner {
    use core::{alloc::Layout, ptr::NonNull};

    use kernel::prelude::*;

    pub(crate) use crate::alloc::{allocator::Kmalloc as Global, AllocError, Allocator, Flags};

    pub(crate) fn do_alloc<A: Allocator>(
        layout: Layout,
        flags: Flags,
    ) -> Result<NonNull<u8>, AllocError> {
        A::alloc(layout, flags).map(|ptr| ptr.cast())
    }
}
