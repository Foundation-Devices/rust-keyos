// FIXME(static_mut_refs): Do not allow `static_mut_refs` lint
#![allow(static_mut_refs)]

use crate::alloc::{GlobalAlloc, Layout, System};

static DLMALLOC: crate::sync::Mutex<dlmalloc::Dlmalloc> =
    crate::sync::Mutex::new(dlmalloc::Dlmalloc::new());

#[stable(feature = "alloc_system_type", since = "1.28.0")]
unsafe impl GlobalAlloc for System {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { DLMALLOC.lock().unwrap().malloc(layout.size(), layout.align()) }
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { DLMALLOC.lock().unwrap().calloc(layout.size(), layout.align()) }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { DLMALLOC.lock().unwrap().free(ptr, layout.size(), layout.align()) }
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        unsafe { DLMALLOC.lock().unwrap().realloc(ptr, layout.size(), layout.align(), new_size) }
    }
}
