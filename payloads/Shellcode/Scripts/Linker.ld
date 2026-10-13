SECTIONS
{
	.text :
	{
		*( .text$A )
		*( .text$B )
		*( .text$C )
		*( .text$D )
		*( .text$E )
		*( .rdata* )
		*( .data* )
		*( .bss* )
		*( .text$F )
	}
}