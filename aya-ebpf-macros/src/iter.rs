use proc_macro2::TokenStream;
use quote::quote;
use syn::{Error, ItemFn, Result};

use crate::args::{err_on_unknown_args, pop_bool_arg, pop_string_arg};

pub(crate) struct Iter {
    item: ItemFn,
    target: String,
    sleepable: bool,
}

impl Iter {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<Iter> {
        let item = syn::parse2(item)?;
        let mut args = syn::parse2(attrs.clone())?;
        let target = pop_string_arg(&mut args, "target")
            .ok_or(Error::new_spanned(attrs, "target has to be specified"))?;
        let sleepable = pop_bool_arg(&mut args, "sleepable");
        err_on_unknown_args(&args)?;
        Ok(Iter {
            item,
            target,
            sleepable,
        })
    }

    pub(crate) fn expand(&self) -> Result<TokenStream> {
        let section_prefix = if self.sleepable { "iter.s" } else { "iter" };
        let section_name = format!("{}/{}", section_prefix, self.target);
        let fn_vis = &self.item.vis;
        let fn_name = self.item.sig.ident.clone();
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #fn_vis fn #fn_name(ctx: *mut ::core::ffi::c_void) -> i32 {
                let _ = #fn_name(::aya_ebpf::programs::IterContext::new(ctx));
                return 0;

                #item
            }
        })
    }
}
