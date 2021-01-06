rule signature_123
{
	meta:
		author = "0xlsd"
		sample = "c1c200f1146789839a5df48adcd02a75a5611cfa8042896af0ab313a39a4c862"
	
	
	strings:
		$string_1 = {
			29 5E ??
			CE
			26 5E
			9E
			C2 29 5E
			82 CE 76
			5E
		}
	
	condition:
		any of them
	
}
