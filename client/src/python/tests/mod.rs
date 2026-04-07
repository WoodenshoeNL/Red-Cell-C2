//! Integration tests for the embedded Python runtime (`crate::python`).
//!
//! Split by area: [`runtime`], [`plugin`], [`callbacks`], [`script`], plus shared [`helpers`].

mod callbacks;
mod helpers;
mod plugin;
mod runtime;
mod script;
