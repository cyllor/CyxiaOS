// Snapshot the committed region, preserving order, offsets and subtraction.
// None means the whole surface; Some(empty) means no input at all.
pub type InputRegionSnapshot = Option<Vec<(bool, i32, i32, i32, i32)>>;
pub fn input_region_snapshot(input: Option<&RegionAttributes>) -> InputRegionSnapshot {
    input.map(|region| region.rects.iter().map(|(kind, rectangle)| {
        (matches!(kind, RectangleKind::Add), rectangle.loc.x, rectangle.loc.y,
         rectangle.size.w, rectangle.size.h)
    }).collect())
}
