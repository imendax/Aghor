rule signature_89
{
	meta:
		author = "0xlsd"
		sample = "6b37c6636ecc81cf044f2670a29937b2043921b609f65f0825112a43dbd9e3ba"
	
	
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
			F3 84 77 ??
			B7 E5
			19 9B ?? ?? ?? ??
		}
	
	condition:
		any of them
	
}
