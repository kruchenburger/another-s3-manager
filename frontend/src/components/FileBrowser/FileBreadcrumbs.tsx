import { Anchor, Breadcrumbs, Text } from "@mantine/core";
import { Link } from "react-router-dom";
import { Home } from "lucide-react";
import { splitCrumbs } from "@/utils/pathUtils";
import classes from "./FileBrowser.module.css";

interface FileBreadcrumbsProps {
  bucket: string;
  roleId: string;
  path: string;
}

export function FileBreadcrumbs({ bucket, roleId, path }: FileBreadcrumbsProps) {
  const crumbs = splitCrumbs(path);
  const baseUrl = `/r/${encodeURIComponent(roleId)}/b/${encodeURIComponent(bucket)}`;

  return (
    // wrap: on phones a deep path folds to a second line instead of
    // overflowing the pinned toolbar row.
    <Breadcrumbs style={{ flexWrap: "wrap", rowGap: 4 }}>
      <Anchor
        component={Link}
        to={baseUrl}
        size="sm"
        className={classes.crumb}
        title={bucket}
      >
        <Home size={14} style={{ verticalAlign: "middle", marginRight: 4 }} />
        {bucket}
      </Anchor>
      {crumbs.map((c, i) => {
        const isLast = i === crumbs.length - 1;
        const url = `${baseUrl}/p/${c.path.split("/").map(encodeURIComponent).join("/")}`;
        return isLast ? (
          <Text
            key={c.path}
            size="sm"
            fw={500}
            className={classes.crumb}
            title={c.name}
          >
            {c.name}
          </Text>
        ) : (
          <Anchor
            component={Link}
            to={url}
            key={c.path}
            size="sm"
            className={classes.crumb}
            title={c.name}
          >
            {c.name}
          </Anchor>
        );
      })}
    </Breadcrumbs>
  );
}
