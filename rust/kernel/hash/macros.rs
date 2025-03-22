// Helper macro for specialization. This also helps avoid parse errors if the
// default fn syntax for specialization changes in the future.
#[cfg(feature = "nightly")]
macro_rules! default_fn {
	(#[$($a:tt)*] $($tt:tt)*) => {
        #[$($a)*] default $($tt)*
    }
}
#[cfg(not(feature = "nightly"))]
macro_rules! default_fn {
	($($tt:tt)*) => {
        $($tt)*
    }
}
