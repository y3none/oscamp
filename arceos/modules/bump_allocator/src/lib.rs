#![no_std]

use allocator::{BaseAllocator, ByteAllocator, PageAllocator};

/// Early memory allocator
/// Use it before formal bytes-allocator and pages-allocator can work!
/// This is a double-end memory range:
/// - Alloc bytes forward
/// - Alloc pages backward
///
/// [ bytes-used | avail-area | pages-used ]
/// |            | -->    <-- |            |
/// start       b_pos        p_pos       end
///
/// For bytes area, 'count' records number of allocations.
/// When it goes down to ZERO, free bytes-used area.
/// For pages area, it will never be freed!
///
/// A [`Result`] type with [`AllocError`] as the error type.
use allocator::AllocError;
pub type AllocResult<T = ()> = Result<T, AllocError>;
use core::alloc::Layout;
use core::ptr::NonNull;
pub struct EarlyAllocator<const PAGE_SIZE: usize>{
    start: usize,
    end: usize,
    bytes_pos: usize,
    pages_pos: usize,
    page_size: usize,
}

impl<const PAGE_SIZE: usize> EarlyAllocator<PAGE_SIZE> {
    /// Creates a new empty `EarlyAllocator`.
    pub const fn new() -> Self {
        Self {
            start: 0,
            end: 0,
            bytes_pos: 0,
            pages_pos: 0,
            page_size: PAGE_SIZE, // standard page size of 4KB
        }
    }
    fn check_overlap(&self, new_start: usize, new_size: usize) -> Result<(), AllocError> {
        if new_start < self.start || (new_start + new_size) > self.end {
            return Err(AllocError::MemoryOverlap);
        }
        if new_start < self.bytes_pos && new_start + new_size > self.bytes_pos {
            return Err(AllocError::MemoryOverlap);
        }
        if new_start < self.end - self.pages_pos * self.page_size && new_start + new_size > self.end - self.pages_pos * self.page_size {
            return Err(AllocError::MemoryOverlap);
        }
        Ok(())
    }
}

impl<const PAGE_SIZE: usize> BaseAllocator for EarlyAllocator<PAGE_SIZE> {
    /// Initialize the allocator with a free memory region.
    fn init(&mut self, start: usize, size: usize){
        self.start = start;
        self.end = start + size;
        self.bytes_pos = start;
        self.pages_pos = 0;
    }

    /// Add a free memory region to the allocator.
    fn add_memory(&mut self, start: usize, size: usize) -> AllocResult{
        self.check_overlap(start, size)?;
        if self.start == 0 && self.end == 0 {
            self.init(start, size);
        } else {
            return Err(AllocError::MemoryOverlap);
        }
        Ok(())
    }
}

impl<const PAGE_SIZE: usize> ByteAllocator for EarlyAllocator<PAGE_SIZE> {
    /// Allocate memory with the given size (in bytes) and alignment.
    fn alloc(&mut self, layout: Layout) -> AllocResult<NonNull<u8>>{
        let size = layout.size();
        let align = layout.align();
 
        if size == 0 || align & (align - 1) != 0 || size & (align - 1) != 0 {
            return Err(AllocError::InvalidParam);
        }
 
        let aligned_pos = (self.bytes_pos + align - 1) & !(align - 1);
        if aligned_pos + size > self.end - self.pages_pos * self.page_size {
            return Err(AllocError::NoMemory);
        }
 
        self.bytes_pos = aligned_pos + size;
        let ptr = unsafe { NonNull::new_unchecked(aligned_pos as *mut u8) };
        Ok(ptr)
    }

    /// Deallocate memory at the given position, size, and alignment.
    fn dealloc(&mut self, pos: NonNull<u8>, layout: Layout){

    }

    /// Returns total memory size in bytes.
    fn total_bytes(&self) -> usize{
        self.end - self.start - self.pages_pos * self.page_size
    }

    /// Returns allocated memory size in bytes.
    fn used_bytes(&self) -> usize{
        self.bytes_pos - self.start
    }

    /// Returns available memory size in bytes.
    fn available_bytes(&self) -> usize{
        self.total_bytes() - self.used_bytes()
    }
}

impl<const PAGE_SIZE: usize> PageAllocator for EarlyAllocator<PAGE_SIZE> {
    /// The size of a memory page.
    const PAGE_SIZE: usize = PAGE_SIZE;

    /// Allocate contiguous memory pages with given count and alignment.
    fn alloc_pages(&mut self, num_pages: usize, align_pow2: usize) -> AllocResult<usize>{
        let needed_space = num_pages * Self::PAGE_SIZE;
        if self.end - self.pages_pos * Self::PAGE_SIZE < needed_space {
            return Err(AllocError::NoMemory);
        }
 
        let pos = self.end - self.pages_pos * Self::PAGE_SIZE - needed_space;
        self.pages_pos += num_pages;
        Ok(pos)
    }

    /// Deallocate contiguous memory pages with given position and count.
    fn dealloc_pages(&mut self, pos: usize, num_pages: usize){

    }

    /// Returns the total number of memory pages.
    fn total_pages(&self) -> usize{
        (self.end - self.start) / Self::PAGE_SIZE
    }

    /// Returns the number of allocated memory pages.
    fn used_pages(&self) -> usize{
        self.pages_pos
    }

    /// Returns the number of available memory pages.
    fn available_pages(&self) -> usize{
        self.total_pages() - self.used_pages()
    }
}
