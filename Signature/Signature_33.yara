rule signature_33
{
	meta:
		author = "0xlsd"
		sample = "0cd547c039ff982b83065e8db30bcc8310f5be7252289aae997c6b7c6bd5d392"
	
	
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
			91
		}
	
	condition:
		any of them
	
}
