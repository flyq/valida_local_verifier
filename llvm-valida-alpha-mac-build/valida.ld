SECTIONS
{
  . = 0x2000000;
  .text 0x0 :
    {
      *(.text)
    }
  .data : { *(.data) }
  .bss : { *(.bss) }
}

INPUT("./DelendumEntryPoint.o")
ENTRY(_start)
