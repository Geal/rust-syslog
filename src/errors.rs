error_chain! {
    errors { Initialization Format Write }

    foreign_links {
        Io(::std::io::Error) #[doc = "Link to a `std::error::Error` type."];
    }
}
