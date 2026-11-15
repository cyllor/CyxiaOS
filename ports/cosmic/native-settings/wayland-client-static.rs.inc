// Cyxia's static client binding retains the upstream function-table API.
// Every entry is the address of a real libwayland-client function. Missing
// target symbols are link failures; this does not implement a dynamic loader.
#[cfg(feature = "cyxia-static-client")]
macro_rules! external_library {
    ($name:ident, $link:expr,
        functions: $( $(#[$attribute:meta])* fn $function:ident($($argument:ty),*) -> $result:ty, )+
        varargs: $( $(#[$variadic_attribute:meta])* fn $variadic:ident($($fixed:ty),+) -> $variadic_result:ty, )+
    ) => {
        pub struct $name {
            $( $(#[$attribute])* pub $function: unsafe extern "C" fn($($argument),*) -> $result, )+
            $( $(#[$variadic_attribute])* pub $variadic: unsafe extern "C" fn($($fixed,)+ ...) -> $variadic_result, )+
        }

        impl $name {
            pub fn linked() -> Self {
                #[link(name = $link, kind = "static")]
                extern "C" {
                    $( $(#[$attribute])* fn $function($(_: $argument),*) -> $result; )+
                    $( $(#[$variadic_attribute])* fn $variadic($(_: $fixed,)+ ...) -> $variadic_result; )+
                }
                Self {
                    $( $(#[$attribute])* $function, )+
                    $( $(#[$variadic_attribute])* $variadic, )+
                }
            }
        }
    };
}

