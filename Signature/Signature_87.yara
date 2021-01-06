rule signature_87
{
	meta:
		author = "0xlsd"
		sample = "3bb25291f4101e89b680654bff51462b336bbf72f5080e7db534cccb70f1a348"
	
	
	strings:
		$string_1 = {
			20 72 ??
			6E
			20 75 ??
			64 65 72 ??
			57
			69 6E ?? 32 0D 0A 24
			37
			00 00
			00 00
			00 00
			00 00
			00 00
			00 00
			00 00
			00 00
			00 00
			00 00
		}
	
	condition:
		any of them
	
}
