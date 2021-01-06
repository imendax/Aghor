rule signature_143
{
	meta:
		author = "0xlsd"
		sample = "0af666f8ddd32a1fd6be708f0ef93ca2587577c593936b1c7efd536e132624c7"
	
	
	strings:
		$string_1 = {
			AA
			88 F4
			35 A3 88 9F 2A
			AA
			88 74 35 ??
			88 9C 2A ?? ?? ?? ??
			63 68 ??
			2A AA ?? ?? ?? ??
			00 00
			00 00
			00 00
			00 00
			00 00
		}
	
	condition:
		any of them
	
}
