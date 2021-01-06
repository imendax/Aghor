rule signature_66
{
	meta:
		author = "0xlsd"
		sample = "43aad379e0ef5cb7f09a6efa77ee3e3ea40ac529ef37efe66d0f96155fe80855"
	
	
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
			34 09
			85 C3
			70 ??
			EB ??
			70 ??
			EB ??
		}
	
	condition:
		any of them
	
}
