import { useMemo, useState, type ReactNode } from 'react';
import { ArrowDown, ArrowUp, ChevronsUpDown } from 'lucide-react';
import { cn } from '@/lib/cn';
import { EmptyState } from './States';

export interface Column<T> {
  id: string;
  header: ReactNode;
  /** Cell renderer. */
  cell: (row: T) => ReactNode;
  /** Provide to make the column sortable. */
  sortValue?: (row: T) => string | number;
  width?: string;
  align?: 'left' | 'right' | 'center';
  /** Hide below the lg breakpoint to keep tables readable on small screens. */
  hideBelowLg?: boolean;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  onRowClick?: (row: T) => void;
  /** Highlights the currently inspected row. */
  activeRowKey?: string | null;
  emptyTitle?: string;
  emptyDescription?: string;
  className?: string;
  /** Caps height and scrolls internally. */
  maxHeight?: string;
  dense?: boolean;
}

/**
 * Sortable, keyboard-navigable table used for IOCs, alerts, cases and
 * intelligence listings.
 */
export function DataTable<T>({
  columns,
  rows,
  rowKey,
  onRowClick,
  activeRowKey,
  emptyTitle = 'No records',
  emptyDescription,
  className,
  maxHeight,
  dense = false,
}: DataTableProps<T>) {
  const [sortId, setSortId] = useState<string | null>(null);
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');

  const sorted = useMemo(() => {
    if (!sortId) return rows;
    const column = columns.find((c) => c.id === sortId);
    if (!column?.sortValue) return rows;
    const getter = column.sortValue;
    return [...rows].sort((a, b) => {
      const av = getter(a);
      const bv = getter(b);
      let result: number;
      if (typeof av === 'number' && typeof bv === 'number') result = av - bv;
      else result = String(av).localeCompare(String(bv), undefined, { numeric: true });
      return sortDir === 'asc' ? result : -result;
    });
  }, [rows, columns, sortId, sortDir]);

  function toggleSort(id: string) {
    if (sortId === id) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortId(id);
      setSortDir('desc');
    }
  }

  if (rows.length === 0) {
    return <EmptyState title={emptyTitle} description={emptyDescription} />;
  }

  const cellPad = dense ? 'px-2.5 py-1.5' : 'px-3 py-2.5';

  return (
    <div
      className={cn('overflow-auto', className)}
      style={maxHeight ? { maxHeight } : undefined}
    >
      <table className="w-full border-collapse text-left text-xs">
        <thead className="sticky top-0 z-10 bg-surface-raised">
          <tr className="border-b border-edge">
            {columns.map((column) => (
              <th
                key={column.id}
                scope="col"
                style={column.width ? { width: column.width } : undefined}
                className={cn(
                  'label-caps whitespace-nowrap font-semibold',
                  cellPad,
                  column.align === 'right' && 'text-right',
                  column.align === 'center' && 'text-center',
                  column.hideBelowLg && 'hidden lg:table-cell',
                )}
              >
                {column.sortValue ? (
                  <button
                    type="button"
                    onClick={() => toggleSort(column.id)}
                    className={cn(
                      'inline-flex items-center gap-1 transition-colors hover:text-intel',
                      sortId === column.id && 'text-intel',
                      column.align === 'right' && 'flex-row-reverse',
                    )}
                  >
                    {column.header}
                    {sortId === column.id ? (
                      sortDir === 'asc' ? (
                        <ArrowUp className="h-3 w-3" />
                      ) : (
                        <ArrowDown className="h-3 w-3" />
                      )
                    ) : (
                      <ChevronsUpDown className="h-3 w-3 opacity-40" />
                    )}
                  </button>
                ) : (
                  column.header
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.map((row) => {
            const key = rowKey(row);
            const active = activeRowKey === key;
            return (
              <tr
                key={key}
                onClick={onRowClick ? () => onRowClick(row) : undefined}
                onKeyDown={
                  onRowClick
                    ? (e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault();
                          onRowClick(row);
                        }
                      }
                    : undefined
                }
                tabIndex={onRowClick ? 0 : undefined}
                className={cn(
                  'border-b border-edge/45 transition-colors',
                  onRowClick && 'cursor-pointer hover:bg-surface-raised/70',
                  active && 'bg-intel/[0.07]',
                )}
              >
                {columns.map((column) => (
                  <td
                    key={column.id}
                    className={cn(
                      'align-middle text-ink-dim',
                      cellPad,
                      column.align === 'right' && 'text-right',
                      column.align === 'center' && 'text-center',
                      column.hideBelowLg && 'hidden lg:table-cell',
                    )}
                  >
                    {column.cell(row)}
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/** Two-column definition list for metadata blocks. */
export function KeyValueList({
  items,
  className,
  dense = false,
}: {
  items: { key: string; value: ReactNode; tone?: 'default' | 'critical' | 'safe' }[];
  className?: string;
  dense?: boolean;
}) {
  return (
    <dl className={cn('divide-y divide-edge/50', className)}>
      {items.map((item) => (
        <div
          key={item.key}
          className={cn(
            'grid grid-cols-[minmax(6.5rem,34%)_1fr] items-baseline gap-3',
            dense ? 'py-1.5' : 'py-2',
          )}
        >
          <dt className="label-caps">{item.key}</dt>
          <dd
            className={cn(
              'min-w-0 break-words text-xs',
              item.tone === 'critical' && 'text-critical',
              item.tone === 'safe' && 'text-safe',
              (!item.tone || item.tone === 'default') && 'text-ink',
            )}
          >
            {item.value}
          </dd>
        </div>
      ))}
    </dl>
  );
}
