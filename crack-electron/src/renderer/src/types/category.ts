export interface Subcategory {
  name: string;
  count: number;
}

export interface CategoryHierarchy {
  category: string;
  totalCount: number;
  subcategories: Subcategory[];
}

export interface CategorySelection {
  category: string | null;
  subcategory: string | null;
}
