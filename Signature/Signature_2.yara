rule signature_2
{
	meta:
		author = "0xlsd"
		sample = "79b417a8e99f72cc682e89fbdbb4262270ee1a24d07c6e3c82a13446a5a683fb"
	
	
	strings:
		$string_1 = {
			69 73 ?? 70 72 6F 67
			72 ??
			6D
			20 63 ??
			6E
			6E
			6F
			74 ??
		}
	
	condition:
		any of them
	
}
