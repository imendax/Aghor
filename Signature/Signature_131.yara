rule signature_131
{
	meta:
		author = "0xlsd"
		sample = "81ce02a5bd8b262d18b506f300ba406921a649bf8ae338c3ac204306e93f8a6e"
	
	
	strings:
		$string_1 = {
			84 CA
			55
			34 85
			CA 5D 34
			84 CA
			4B
			66 07
			CA 54 34
			84 CA
			55
			34 84
			CA 54 34
			84 CA
			4B
			66 10 CA
			54
			34 84
			CA 4B 66
		}
	
	condition:
		any of them
	
}
