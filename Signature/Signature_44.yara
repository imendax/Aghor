rule signature_44
{
	meta:
		author = "0xlsd"
		sample = "deba7fcb1f196a58289f8f9399e823a24a56fc0e934404399ef87ad419fe2e65"
	
	
	strings:
		$string_1 = {
			1A 8F ?? ?? ?? ??
			BD 18 1A 8F D9
			DE 61 ??
			FB
			18 1A
		}
	
	condition:
		any of them
	
}
