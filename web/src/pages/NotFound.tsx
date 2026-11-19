import { Link } from "react-router-dom";

import { EmptyState } from "../components/ui";

export function NotFoundPage() {
  return (
    <EmptyState title="Страница не найдена">
      <Link to="/" className="link">
        На главную
      </Link>
    </EmptyState>
  );
}
