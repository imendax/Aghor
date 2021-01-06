rule signature_23
{
	meta:
		author = "0xlsd"
		sample = "9201aac8ab19bd963bfabd15a89037a0f5ee0050f651bcfe99127ec0d99053fe"
	
	
	strings:
		$string_1 = {
			20 72 ??
			6E
			20 69 ??
			20 44 4F ??
			20 6D ??
			64 65 2E 0D 0D 0A 24 00
			00 00
			00 00
			00 00
			9E
			43
		}
	
	condition:
		any of them
	
}
