rule signature_109
{
	meta:
		author = "0xlsd"
		sample = "20fae67bbce8bea85442d3315d1015e286792bbef05f6ed2392258af10ab2a84"
	
	
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
			BF 8D 31 83 FB
			EC
			5F
			D0 FB
			EC
			5F
		}
	
	condition:
		any of them
	
}
