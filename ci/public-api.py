#!/usr/bin/env python3
"""Render the crate's public API surface as a sorted, diffable text snapshot.

The snapshot is the pin that makes an API change deliberate. Rust's semver tooling
sees a signature; nothing in a build sees an item that became public because a
private module was glob-re-exported, or an item that quietly disappeared. This
renders every item reachable at a public path — modules, types, fields, variants,
associated items, trait implementations — one per line, and the gate diffs it
against the committed file.

Input is rustdoc's JSON output, which is nightly-only and versioned: the script
asserts the format version it was written against rather than guessing at a
changed schema. Regenerate with `ci/public-api.sh --bless`.

Two details the snapshot carries deliberately, because both are contracts this
crate makes and neither is visible in a signature:

- `#[non_exhaustive]`, on items and on individual enum variants. Whether a type
  can grow a field is the property that decides if a future change is a patch or
  a major bump, so it belongs in the pin.
- Every public path an item is reachable by. A type re-exported under two paths
  gets two lines, so a facade that widens the surface shows up as added lines
  rather than as nothing at all.
"""

from __future__ import annotations

import json
import sys

# The rustdoc JSON schema this renderer reads. Rustdoc bumps it whenever the shape
# changes, so a mismatch means the renderer is reading fields that may have moved:
# fail loudly instead of emitting a snapshot built from a misread document.
FORMAT_VERSION = 60

# Traits every type gets from the compiler or a blanket impl. Listing them would
# bury the deliberate impls in noise that no change of ours can affect.
AUTO_TRAITS = {
    "Send",
    "Sync",
    "Unpin",
    "UnwindSafe",
    "RefUnwindSafe",
    "UnsafeUnpin",
    "Freeze",
    # A compiler-internal marker `derive(PartialEq)` emits; not something a consumer
    # names or a change of ours controls.
    "StructuralPartialEq",
}


class Renderer:
    def __init__(self, doc: dict) -> None:
        self.index: dict[int, dict] = {int(k): v for k, v in doc["index"].items()}
        self.paths: dict[int, dict] = {int(k): v for k, v in doc["paths"].items()}
        self.root: int = doc["root"]
        self.lines: set[str] = set()
        # (item id, path) pairs already rendered. A type reachable by two paths is
        # rendered under both; the same type at the same path is rendered once, which
        # is what stops a re-export cycle.
        self.seen: set[tuple[int, str]] = set()

    # ── entry point ──

    def render(self) -> list[str]:
        crate_name = self.index[self.root]["name"]
        self.walk_module(self.root, crate_name)
        return sorted(self.lines)

    def emit(self, line: str) -> None:
        self.lines.add(" ".join(line.split()))

    # ── module traversal ──

    def walk_module(self, item_id: int, path: str) -> None:
        item = self.index.get(item_id)
        if item is None:
            return
        self.emit(f"pub mod {path}")
        for child_id in item["inner"]["module"]["items"]:
            self.walk_item(child_id, path)

    def walk_item(self, item_id: int, parent_path: str) -> None:
        item = self.index.get(item_id)
        if item is None:
            # An item rustdoc did not index is one from another crate; a public
            # re-export of one is named by its path table entry instead.
            summary = self.paths.get(item_id)
            if summary is not None:
                self.emit(f"pub use {parent_path}::{'::'.join(summary['path'])}")
            return
        if item["visibility"] != "public" and "use" not in item["inner"]:
            return

        kind, inner = next(iter(item["inner"].items()))

        if kind == "use":
            self.walk_use(inner, parent_path)
            return

        name = item["name"]
        if name is None:
            return
        path = f"{parent_path}::{name}"
        if (item_id, path) in self.seen:
            return
        self.seen.add((item_id, path))

        if kind == "module":
            self.walk_module(item_id, path)
        elif kind == "struct":
            self.render_struct(item, inner, path)
        elif kind == "enum":
            self.render_enum(item, inner, path)
        elif kind == "trait":
            self.render_trait(item, inner, path)
        elif kind == "function":
            self.emit(f"pub {self.fn_signature(item, inner, path)}")
        elif kind == "constant":
            self.emit(f"pub const {path}: {self.ty(inner['type'])}")
        elif kind == "type_alias":
            self.emit(f"pub type {path} = {self.ty(inner['type'])}")
        elif kind == "macro":
            self.emit(f"pub macro {path}!")
        elif kind == "trait_alias":
            self.emit(f"pub trait alias {path}")

    def walk_use(self, use: dict, parent_path: str) -> None:
        target = use["id"]
        if use["is_glob"]:
            # `pub use module::*` — the items land directly in the importing module,
            # so they are walked under the importing module's path, not the source's.
            source = self.index.get(target)
            if source is None:
                return
            source_kind, source_inner = next(iter(source["inner"].items()))
            if source_kind == "module":
                for child_id in source_inner["items"]:
                    self.walk_item(child_id, parent_path)
            elif source_kind == "enum":
                for variant_id in source_inner["variants"]:
                    self.walk_item(variant_id, parent_path)
            return
        item = self.index.get(target)
        if item is None:
            summary = self.paths.get(target)
            if summary is not None:
                self.emit(f"pub use {parent_path}::{use['name']} = {'::'.join(summary['path'])}")
            return
        # A renamed or re-exported item is rendered under the name it is reachable by
        # here, which is the name a consumer writes.
        renamed = dict(item)
        renamed["name"] = use["name"]
        self.walk_item_as(renamed, target, parent_path)

    def walk_item_as(self, item: dict, item_id: int, parent_path: str) -> None:
        """Render `item` under `parent_path` using the (possibly renamed) item name."""
        kind, inner = next(iter(item["inner"].items()))
        name = item["name"]
        if name is None:
            return
        path = f"{parent_path}::{name}"
        if (item_id, path) in self.seen:
            return
        self.seen.add((item_id, path))
        if kind == "module":
            self.emit(f"pub mod {path}")
            for child_id in inner["items"]:
                self.walk_item(child_id, path)
        elif kind == "struct":
            self.render_struct(item, inner, path)
        elif kind == "enum":
            self.render_enum(item, inner, path)
        elif kind == "trait":
            self.render_trait(item, inner, path)
        elif kind == "function":
            self.emit(f"pub {self.fn_signature(item, inner, path)}")
        elif kind == "constant":
            self.emit(f"pub const {path}: {self.ty(inner['type'])}")
        elif kind == "type_alias":
            self.emit(f"pub type {path} = {self.ty(inner['type'])}")
        elif kind == "variant":
            self.render_variant(item, inner, path)

    # ── type items ──

    def attr_prefix(self, item: dict) -> str:
        return "#[non_exhaustive] " if "non_exhaustive" in item.get("attrs", []) else ""

    def render_struct(self, item: dict, inner: dict, path: str) -> None:
        prefix = self.attr_prefix(item)
        generics = self.generics(inner["generics"])
        struct_kind = inner["kind"]
        if "unit" in struct_kind:
            self.emit(f"{prefix}pub struct {path}{generics}")
        elif "tuple" in struct_kind:
            fields = struct_kind["tuple"]
            rendered = ", ".join(
                self.field_type(f) if f is not None else "/* private */" for f in fields
            )
            self.emit(f"{prefix}pub struct {path}{generics}({rendered})")
        else:
            plain = struct_kind["plain"]
            private = " { /* private fields */ }" if plain["has_stripped_fields"] else ""
            self.emit(f"{prefix}pub struct {path}{generics}{private}")
            for field_id in plain["fields"]:
                field = self.index.get(field_id)
                if field is None or field["visibility"] != "public":
                    continue
                ty = self.ty(field["inner"]["struct_field"])
                self.emit(f"pub {path}::{field['name']}: {ty}")
        self.render_impls(inner.get("impls", []), path)

    def render_enum(self, item: dict, inner: dict, path: str) -> None:
        self.emit(f"{self.attr_prefix(item)}pub enum {path}{self.generics(inner['generics'])}")
        for variant_id in inner["variants"]:
            variant = self.index.get(variant_id)
            if variant is None:
                continue
            self.render_variant(variant, variant["inner"]["variant"], f"{path}::{variant['name']}")
        self.render_impls(inner.get("impls", []), path)

    def render_variant(self, item: dict, inner: dict, path: str) -> None:
        prefix = self.attr_prefix(item)
        kind = inner["kind"]
        if "plain" in kind:
            self.emit(f"{prefix}pub {path}")
        elif "tuple" in kind:
            # A variant's fields carry the enum's visibility rather than their own, so
            # they are rendered unconditionally: a tuple variant has no private fields.
            rendered = ", ".join(
                self.variant_field_type(f) if f is not None else "_" for f in kind["tuple"]
            )
            self.emit(f"{prefix}pub {path}({rendered})")
        else:
            private = " { /* private fields */ }" if kind["struct"]["has_stripped_fields"] else ""
            self.emit(f"{prefix}pub {path}{private}")
            for field_id in kind["struct"]["fields"]:
                field = self.index.get(field_id)
                if field is None:
                    continue
                ty = self.ty(field["inner"]["struct_field"])
                self.emit(f"pub {path}::{field['name']}: {ty}")

    def render_trait(self, item: dict, inner: dict, path: str) -> None:
        prefix = self.attr_prefix(item)
        unsafe = "unsafe " if inner["is_unsafe"] else ""
        bounds = self.bounds(inner.get("bounds", []))
        supertraits = f": {bounds}" if bounds else ""
        self.emit(
            f"{prefix}pub {unsafe}trait {path}{self.generics(inner['generics'])}{supertraits}"
        )
        for member_id in inner["items"]:
            member = self.index.get(member_id)
            if member is None:
                continue
            self.render_assoc(member, f"{path}::{member['name']}", in_trait=True)

    def render_impls(self, impl_ids: list[int], path: str) -> None:
        for impl_id in impl_ids:
            impl_item = self.index.get(impl_id)
            if impl_item is None:
                continue
            impl = impl_item["inner"]["impl"]
            if impl["is_synthetic"] or impl.get("blanket_impl") is not None:
                continue
            trait = impl.get("trait")
            if trait is None:
                for member_id in impl["items"]:
                    member = self.index.get(member_id)
                    if member is None or member["visibility"] != "public":
                        continue
                    self.render_assoc(member, f"{path}::{member['name']}", in_trait=False)
                continue
            trait_name = trait["path"]
            if trait_name in AUTO_TRAITS:
                continue
            negative = "!" if impl["is_negative"] else ""
            args = self.generic_args(trait.get("args"))
            self.emit(f"impl {negative}{trait_name}{args} for {path}")

    def render_assoc(self, member: dict, path: str, *, in_trait: bool = False) -> None:
        """Render one associated item. Trait members are public by definition, so both
        an inherent method and a trait method read as `pub`; `/* required */` is what
        separates a method an implementor must write from one with a default body."""
        kind, inner = next(iter(member["inner"].items()))
        if kind == "function":
            required = "" if inner.get("has_body", True) else " /* required */"
            self.emit(f"pub {self.fn_signature(member, inner, path)}{required}")
        elif kind == "assoc_const":
            self.emit(f"pub const {path}: {self.ty(inner['type'])}")
        elif kind == "assoc_type":
            bounds = self.bounds(inner.get("bounds", []))
            suffix = f": {bounds}" if bounds else ""
            self.emit(f"pub type {path}{suffix}")

    # ── signatures ──

    def fn_signature(self, item: dict, inner: dict, path: str) -> str:
        header = inner["header"]
        qualifiers = ""
        if header["is_const"]:
            qualifiers += "const "
        if header["is_async"]:
            qualifiers += "async "
        if header["is_unsafe"]:
            qualifiers += "unsafe "
        sig = inner["sig"]
        params = []
        for name, ty in sig["inputs"]:
            rendered = self.ty(ty)
            if name == "self":
                params.append(self.self_param(rendered))
            else:
                params.append(f"{name}: {rendered}")
        if sig["is_c_variadic"]:
            params.append("...")
        output = sig.get("output")
        ret = f" -> {self.ty(output)}" if output is not None else ""
        where = self.where_clause(inner["generics"])
        return (
            f"{qualifiers}fn {path}{self.generics(inner['generics'])}"
            f"({', '.join(params)}){ret}{where}"
        )

    @staticmethod
    def self_param(rendered: str) -> str:
        if rendered == "Self":
            return "self"
        if rendered == "&Self":
            return "&self"
        if rendered == "&mut Self":
            return "&mut self"
        return f"self: {rendered}"

    # ── generics ──

    def generics(self, generics: dict | None) -> str:
        if not generics:
            return ""
        params = []
        for param in generics["params"]:
            kind, inner = next(iter(param["kind"].items()))
            if kind == "lifetime":
                params.append(param["name"])
            elif kind == "type":
                if inner.get("is_synthetic"):
                    continue
                bounds = self.bounds(inner.get("bounds", []))
                params.append(f"{param['name']}: {bounds}" if bounds else param["name"])
            elif kind == "const":
                params.append(f"const {param['name']}: {self.ty(inner['type'])}")
        return f"<{', '.join(params)}>" if params else ""

    def where_clause(self, generics: dict | None) -> str:
        if not generics:
            return ""
        clauses = []
        for predicate in generics["where_predicates"]:
            kind, inner = next(iter(predicate.items()))
            if kind == "bound_predicate":
                bounds = self.bounds(inner["bounds"])
                clauses.append(f"{self.ty(inner['type'])}: {bounds}")
            elif kind == "lifetime_predicate":
                clauses.append(f"{inner['lifetime']}: {' + '.join(inner['outlives'])}")
            elif kind == "eq_predicate":
                clauses.append(f"{self.ty(inner['lhs'])} == {self.term(inner['rhs'])}")
        return f" where {', '.join(clauses)}" if clauses else ""

    def bounds(self, bounds: list[dict]) -> str:
        rendered = []
        for bound in bounds:
            kind, inner = next(iter(bound.items()))
            if kind == "trait_bound":
                modifier = inner.get("modifier", "none")
                prefix = "?" if modifier == "maybe" else ""
                path = inner["trait"]
                rendered.append(f"{prefix}{path['path']}{self.generic_args(path.get('args'))}")
            elif kind == "outlives":
                rendered.append(inner)
            elif kind == "use":
                rendered.append("use<..>")
        return " + ".join(rendered)

    def term(self, term: dict) -> str:
        kind, inner = next(iter(term.items()))
        if kind == "type":
            return self.ty(inner)
        return str(inner.get("expr", inner))

    def generic_args(self, args: dict | None) -> str:
        if args is None:
            return ""
        kind, inner = next(iter(args.items()))
        if kind == "angle_bracketed":
            rendered = []
            for arg in inner["args"]:
                arg_kind, arg_inner = next(iter(arg.items()))
                if arg_kind == "lifetime":
                    rendered.append(arg_inner)
                elif arg_kind == "type":
                    rendered.append(self.ty(arg_inner))
                elif arg_kind == "const":
                    rendered.append(arg_inner["expr"])
                else:
                    rendered.append("_")
            for constraint in inner["constraints"]:
                binding_kind, binding = next(iter(constraint["binding"].items()))
                if binding_kind == "equality":
                    rendered.append(f"{constraint['name']} = {self.term(binding)}")
                else:
                    rendered.append(f"{constraint['name']}: {self.bounds(binding)}")
            return f"<{', '.join(rendered)}>" if rendered else ""
        inputs = ", ".join(self.ty(t) for t in inner["inputs"])
        output = inner.get("output")
        ret = f" -> {self.ty(output)}" if output is not None else ""
        return f"({inputs}){ret}"

    # ── types ──

    def ty(self, ty: dict | None) -> str:
        if ty is None:
            return "()"
        kind, inner = next(iter(ty.items()))
        if kind == "resolved_path":
            return f"{inner['path']}{self.generic_args(inner.get('args'))}"
        if kind == "generic":
            return inner
        if kind == "primitive":
            return inner
        if kind == "borrowed_ref":
            lifetime = f"{inner['lifetime']} " if inner.get("lifetime") else ""
            mutable = "mut " if inner["is_mutable"] else ""
            return f"&{lifetime}{mutable}{self.ty(inner['type'])}"
        if kind == "raw_pointer":
            mutable = "mut" if inner["is_mutable"] else "const"
            return f"*{mutable} {self.ty(inner['type'])}"
        if kind == "slice":
            return f"[{self.ty(inner)}]"
        if kind == "array":
            return f"[{self.ty(inner['type'])}; {inner['len']}]"
        if kind == "tuple":
            if not inner:
                return "()"
            if len(inner) == 1:
                return f"({self.ty(inner[0])},)"
            return f"({', '.join(self.ty(t) for t in inner)})"
        if kind == "dyn_trait":
            traits = " + ".join(
                f"{t['trait']['path']}{self.generic_args(t['trait'].get('args'))}"
                for t in inner["traits"]
            )
            lifetime = f" + {inner['lifetime']}" if inner.get("lifetime") else ""
            return f"dyn {traits}{lifetime}"
        if kind == "impl_trait":
            return f"impl {self.bounds(inner)}"
        if kind == "infer":
            return "_"
        if kind == "qualified_path":
            self_ty = self.ty(inner["self_type"])
            trait = inner.get("trait")
            if trait is None:
                return f"{self_ty}::{inner['name']}"
            return f"<{self_ty} as {trait['path']}>::{inner['name']}"
        if kind == "function_pointer":
            sig = inner["sig"]
            inputs = ", ".join(self.ty(t) for _, t in sig["inputs"])
            output = sig.get("output")
            ret = f" -> {self.ty(output)}" if output is not None else ""
            return f"fn({inputs}){ret}"
        if kind == "pat":
            return self.ty(inner["type"])
        return f"/* {kind} */"

    def field_type(self, field_id: int) -> str:
        field = self.index.get(field_id)
        if field is None or field["visibility"] != "public":
            return "/* private */"
        return self.ty(field["inner"]["struct_field"])

    def variant_field_type(self, field_id: int) -> str:
        field = self.index.get(field_id)
        if field is None:
            return "_"
        return self.ty(field["inner"]["struct_field"])


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: public-api.py <rustdoc-json-file>", file=sys.stderr)
        return 2
    with open(sys.argv[1], encoding="utf-8") as handle:
        doc = json.load(handle)
    found = doc.get("format_version")
    if found != FORMAT_VERSION:
        print(
            f"rustdoc JSON format_version {found}, expected {FORMAT_VERSION}: "
            "the pinned nightly moved. Re-read the renderer against the new schema, "
            "update FORMAT_VERSION, and re-bless the snapshot.",
            file=sys.stderr,
        )
        return 2
    for line in Renderer(doc).render():
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
