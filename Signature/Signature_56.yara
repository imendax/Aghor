rule signature_56
{
	meta:
		author = "0xlsd"
		sample = "fbec1aaa71eb97c3380529c39cf523ffdc93b8087333b707366e6583ad9cddc3"
	
	
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
			5B
			CB
			1A 03
			1F
			AA
			74 ??
			1F
			AA
			74 ??
		}
	
	condition:
		any of them
	
}
