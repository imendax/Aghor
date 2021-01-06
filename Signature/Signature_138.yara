rule signature_138
{
	meta:
		author = "0xlsd"
		sample = "bf13d7157fac8f2215eab571e28c08a45eaae020ca451bdf4c334a73076ea9d9"
	
	
	strings:
		$string_1 = {
			17
			89 E0
			BC 1E 89 8D A3
			17
			89 60 ??
			1A 89 ?? ?? ?? ??
			52
			69 63 ?? 89 A3 17 89
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
