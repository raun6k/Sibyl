import { Children, isValidElement, type ComponentProps, type ReactNode } from "react"
import { Select as SelectPrimitive } from "radix-ui"
import { Check, ChevronDown, ChevronUp } from "lucide-react"
import { cn } from "@/lib/utils"

type SelectProps = Pick<ComponentProps<"button">, "id" | "className" | "disabled" | "aria-label" | "aria-labelledby" | "aria-describedby"> & {
  name?: string
  value?: string | number
  defaultValue?: string | number
  onValueChange?: (value: string) => void
  children: ReactNode
}

// Keep option content at the call site; Radix supplies focus, typeahead and form integration.
export function Select({ children, value, defaultValue, onValueChange, name, className, disabled, ...props }: SelectProps) {
  return (
    <SelectPrimitive.Root name={name} value={value == null ? undefined : String(value)} defaultValue={defaultValue == null ? undefined : String(defaultValue)} onValueChange={onValueChange} disabled={disabled}>
      <SelectPrimitive.Trigger {...props} className={cn("group flex min-h-10 w-full min-w-0 items-center justify-between gap-3 rounded-lg border border-border bg-panel px-3 py-2 text-left text-sm font-medium text-foreground transition-colors hover:border-input hover:bg-raised focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring data-[state=open]:border-primary/60 data-[state=open]:bg-raised disabled:cursor-not-allowed disabled:opacity-50 [&>span:first-child]:truncate", className)}>
        <SelectPrimitive.Value />
        <SelectPrimitive.Icon asChild><ChevronDown className="size-4 shrink-0 text-muted-foreground transition-transform group-data-[state=open]:rotate-180" aria-hidden="true" /></SelectPrimitive.Icon>
      </SelectPrimitive.Trigger>
      <SelectPrimitive.Portal>
        <SelectPrimitive.Content position="popper" sideOffset={6} collisionPadding={12} className="z-[100] max-h-[var(--radix-select-content-available-height)] min-w-[var(--radix-select-trigger-width)] max-w-[calc(100vw-24px)] overflow-hidden rounded-xl bg-popover p-1.5 text-popover-foreground shadow-[0_12px_32px_-8px_rgba(0,0,0,0.45)] ring-1 ring-border">
          <SelectPrimitive.ScrollUpButton className="flex h-6 items-center justify-center text-muted-foreground"><ChevronUp className="size-4" /></SelectPrimitive.ScrollUpButton>
          <SelectPrimitive.Viewport>
            {Children.map(children, (child) => {
              if (!isValidElement<ComponentProps<"option">>(child) || child.type !== "option") return null
              return (
                <SelectPrimitive.Item style={{ outline: "none" }} key={String(child.props.value)} value={String(child.props.value)} disabled={child.props.disabled} className="relative flex min-h-10 cursor-pointer select-none items-center rounded-lg py-2 pl-3 pr-9 text-sm outline-none data-[highlighted]:bg-primary/10 data-[highlighted]:text-primary data-[state=checked]:font-medium data-[disabled]:pointer-events-none data-[disabled]:opacity-50">
                  <SelectPrimitive.ItemText>{child.props.children}</SelectPrimitive.ItemText>
                  <SelectPrimitive.ItemIndicator className="absolute right-3 flex items-center text-primary"><Check className="size-4" aria-hidden="true" /></SelectPrimitive.ItemIndicator>
                </SelectPrimitive.Item>
              )
            })}
          </SelectPrimitive.Viewport>
          <SelectPrimitive.ScrollDownButton className="flex h-6 items-center justify-center text-muted-foreground"><ChevronDown className="size-4" /></SelectPrimitive.ScrollDownButton>
        </SelectPrimitive.Content>
      </SelectPrimitive.Portal>
    </SelectPrimitive.Root>
  )
}
