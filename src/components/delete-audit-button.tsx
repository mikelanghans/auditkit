import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Trash2, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

type Props = {
  auditId: string;
  title?: string;
  /** "button" → labelled outline button (detail page). "icon" → small icon-only button (lists). */
  variant?: "button" | "icon";
  /** Where to go after a successful delete. Omit to stay in place (lists). */
  redirectTo?: string;
  className?: string;
};

export function DeleteAuditButton({
  auditId,
  title,
  variant = "button",
  redirectTo,
  className,
}: Props) {
  const [open, setOpen] = useState(false);
  const qc = useQueryClient();
  const navigate = useNavigate();

  const del = useMutation({
    mutationFn: async () => {
      const { error } = await supabase.from("audits").delete().eq("id", auditId);
      if (error) throw error;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["audits"] });
      qc.invalidateQueries({ queryKey: ["client-audits"] });
      toast.success("Audit deleted");
      setOpen(false);
      if (redirectTo) navigate({ to: redirectTo });
    },
    onError: (e: any) => toast.error(e?.message ?? "Failed to delete audit"),
  });

  return (
    <AlertDialog open={open} onOpenChange={(o) => !del.isPending && setOpen(o)}>
      <AlertDialogTrigger asChild onClick={(e) => e.stopPropagation()}>
        {variant === "icon" ? (
          <Button
            variant="ghost"
            size="icon"
            aria-label="Delete audit"
            className={cn("h-8 w-8 text-muted-foreground hover:text-status-fail hover:bg-status-fail/10", className)}
            onClick={(e) => { e.preventDefault(); e.stopPropagation(); setOpen(true); }}
          >
            <Trash2 className="h-4 w-4" />
          </Button>
        ) : (
          <Button
            variant="outline"
            className={cn("text-status-fail hover:text-status-fail hover:bg-status-fail/10 border-status-fail/30", className)}
          >
            <Trash2 className="h-4 w-4 mr-1" /> Delete
          </Button>
        )}
      </AlertDialogTrigger>
      <AlertDialogContent onClick={(e) => e.stopPropagation()}>
        <AlertDialogHeader>
          <AlertDialogTitle>Delete this audit?</AlertDialogTitle>
          <AlertDialogDescription>
            {title ? <><strong>{title}</strong> and all of its findings will be permanently removed. </> : "All findings for this audit will be permanently removed. "}
            This cannot be undone.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={del.isPending}>Cancel</AlertDialogCancel>
          <AlertDialogAction
            disabled={del.isPending}
            onClick={(e) => { e.preventDefault(); del.mutate(); }}
            className="bg-status-fail text-white hover:bg-status-fail/90"
          >
            {del.isPending ? <><Loader2 className="h-4 w-4 mr-1 animate-spin" /> Deleting…</> : <><Trash2 className="h-4 w-4 mr-1" /> Delete audit</>}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
